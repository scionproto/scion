# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from lib.packet.path_mgmt import PathMgmtPacket
"""
:mod:`router` --- SCION edge router
===========================================
"""

import argparse
import datetime
import logging
import socket
import sys
import threading
import time

from infrastructure.scion_elem import SCIONElement
from lib.crypto.symcrypto import get_roundkey_cache, verify_of_mac
from lib.defines import SCION_UDP_PORT, EXP_TIME_UNIT, SCION_UDP_EH_DATA_PORT
from lib.log import init_logging, log_exception
from lib.packet.opaque_field import OpaqueFieldType as OFT
from lib.packet.pcb import PathConstructionBeacon
from lib.packet.scion import (
    IFIDPacket,
    PacketType as PT,
    SCIONPacket,
    get_type,
)
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.thread import thread_safety_net
from lib.util import handle_signals, SCIONTime

IFID_PKT_TOUT = 1  # How often IFID packet is sent to neighboring router.


class Router(SCIONElement):
    """
    The SCION Router.

    :ivar addr: the router address.
    :type addr: :class:`SCIONAddr`
    :ivar topology: the AD topology as seen by the router.
    :type topology: :class:`Topology`
    :ivar config: the configuration of the router.
    :type config: :class:`Config`
    :ivar ifid2addr: a map from interface identifiers to the corresponding
                     border router addresses in the server's AD.
    :type ifid2addr: dict
    :ivar interface: the router's inter-AD interface, if any.
    :type interface: :class:`lib.topology.InterfaceElement`
    :ivar pre_ext_handlers: a map of extension header types to handlers for
                            those extensions that execute before routing.
    :type pre_ext_handlers: dict
    :ivar post_ext_handlers: a map of extension header types to handlers for
                             those extensions that execute after routing.
    :type post_ext_handlers: dict
    """
    def __init__(self, router_id, topo_file, config_file, pre_ext_handlers=None,
                 post_ext_handlers=None, is_sim=False):
        """
        Initialize an instance of the class Router.

        :param router_id:
        :type router_id:
        :param topo_file: the topology file name.
        :type topo_file: str
        :param config_file: the configuration file name.
        :type config_file: str
        :param pre_ext_handlers: a map of extension header types to handlers
                                 for those extensions that execute before
                                 routing.
        :type pre_ext_handlers: dict
        :param post_ext_handlers: a map of extension header types to handlers
                                  for those extensions that execute after
                                  routing.
        :type post_ext_handlers: dict
        :param is_sim: running in simulator
        :type is_sim: bool
        """
        SCIONElement.__init__(self, "er", topo_file, server_id=router_id,
                              config_file=config_file, is_sim=is_sim)
        self.interface = None
        for edge_router in self.topology.get_all_edge_routers():
            if edge_router.addr == self.addr.host_addr:
                self.interface = edge_router.interface
                break
        assert self.interface is not None
        logging.info("Interface: %s", self.interface.__dict__)
        self.of_gen_key = get_roundkey_cache(self.config.master_ad_key)
        if pre_ext_handlers:
            self.pre_ext_handlers = pre_ext_handlers
        else:
            self.pre_ext_handlers = {}
        if post_ext_handlers:
            self.post_ext_handlers = post_ext_handlers
        else:
            self.post_ext_handlers = {}
        if not is_sim:
            self._remote_socket = socket.socket(socket.AF_INET,
                                                socket.SOCK_DGRAM)
            self._remote_socket.setsockopt(socket.SOL_SOCKET,
                                           socket.SO_REUSEADDR, 1)
            self._remote_socket.bind((str(self.interface.addr),
                                      self.interface.udp_port))
            self._sockets.append(self._remote_socket)
            logging.info("IP %s:%u", self.interface.addr,
                         self.interface.udp_port)

    def run(self):
        """
        Run the router threads.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.sync_interface,),
            name="ER.sync_interface", daemon=True).start()
        SCIONElement.run(self)

    def send(self, packet, addr, port=SCION_UDP_PORT, use_local_socket=True):
        """
        Send a packet to addr (class of that object must implement
        __str__ which returns IPv4 addr) using port and local or remote
        socket.

        :param packet: The packet to send.
        :type packet: :class:`lib.packet.SCIONPacket`
        :param addr: The address of the next hop.
        :type addr: :class:`IPv4Adress`
        :param port: The port number of the next hop.
        :type port: int
        :param use_local_socket: whether to use the local socket (as opposed to
                                 a remote socket).
        :type use_local_socket: bool
        """
        if use_local_socket:
            SCIONElement.send(self, packet, addr, port)
        else:
            self._remote_socket.sendto(
                packet.pack(), (str(addr), port))

    def sync_interface(self):
        """
        Synchronize and initialize the router's interface with that of a
        neighboring router.
        """
        src = SCIONAddr.from_values(self.topology.isd_id, self.topology.ad_id,
                                    self.interface.addr)
        dst_isd_ad = ISD_AD(self.interface.neighbor_isd,
                            self.interface.neighbor_ad)
        ifid_req = IFIDPacket.from_values(src, dst_isd_ad, self.interface.if_id)
        while True:
            self.send(ifid_req, self.interface.to_addr,
                      self.interface.to_udp_port, False)
            logging.info('Sending IFID_PKT to router: req_id:%d, rep_id:%d',
                         ifid_req.request_id, ifid_req.reply_id)
            time.sleep(IFID_PKT_TOUT)

    def process_ifid_request(self, packet):
        """
        After receiving IFID_PKT from neighboring router it is completed (by
        iface information) and passed to local BSes.

        :param packet: the IFID request packet to send.
        :type packet: bytes
        """
        ifid_req = IFIDPacket(packet)
        # Forward 'alive' packet to all BSes (to inform that neighbor is alive).
        ifid_req.reply_id = self.interface.if_id  # BS must determine interface.
        for bs in self.topology.beacon_servers:
            self.send(ifid_req, bs.addr)

    def process_pcb(self, packet, from_bs):
        """
        Depending on scenario: a) send PCB to all beacon servers, or b) to
        neighboring router.

        :param packet: The PCB.
        :type packet: :class:`lib.packet.SCIONPacket`
        :param from_bs: True, if the beacon was received from local BS.
        :type from_bs: bool
        """
        beacon = PathConstructionBeacon(packet)
        if from_bs:
            if self.interface.if_id != beacon.pcb.get_last_pcbm().hof.egress_if:
                logging.error("Wrong interface set by BS.")
                return
            self.send(beacon, self.interface.to_addr,
                      self.interface.to_udp_port, False)
        else:
            # TODO Multiple BS scenario
            beacon.pcb.if_id = self.interface.if_id
            self.send(beacon, self.topology.beacon_servers[0].addr)

    def relay_cert_server_packet(self, spkt, from_local_ad):
        """
        Relay packets for certificate servers.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        if from_local_ad:
            addr = self.interface.to_addr
            port = self.interface.to_udp_port
        else:
            # TODO Multiple CS scenario
            addr = self.topology.certificate_servers[0].addr
            port = SCION_UDP_PORT
        self.send(spkt, addr, port)

    def process_path_mgmt_packet(self, spkt, from_local_ad):
        """
        Process path management packets.

        :param spkt: The path mgmt packet.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        # For now this function only forwards path management packets to the
        # path servers in the destination AD. In the future, path management
        # packets might be handled differently.
        mgmt_pkt = PathMgmtPacket(spkt.raw)
        if not from_local_ad and mgmt_pkt.hdr.is_last_path_of():
            self.terminate(spkt, PT.PATH_MGMT)
        else:
            self.forward_packet(spkt, from_local_ad)

    def verify_of(self, hof, prev_hof, ts):
        """
        Verify freshness and authentication of an opaque field.

        :param hof: the hop opaque field that is verified.
        :type hof: :class:`lib.packet.opaque_field.HopOpaqueField`
        :param prev_hof: previous hop opaque field (according to order of PCB
                         propagation) required for verification.
        :type prev_hof: :class:`lib.packet.opaque_field.HopOpaqueField` or None
        :param ts: timestamp against which the opaque field is verified.
        :type ts: int
        """
        if int(SCIONTime.get_time()) <= ts + hof.exp_time * EXP_TIME_UNIT:
            if verify_of_mac(self.of_gen_key, hof, prev_hof, ts):
                return True
            else:
                logging.warning("Dropping packet due to incorrect MAC.")
        else:
            logging.warning("Dropping packet due to expired OF.")
        return False

    def terminate(self, spkt, ptype):
        """
        Forwards the packet to the end destination within the current AD.

        :param spkt: The SCION Packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param ptype: The packet type.
        :type ptype: int
        """
        curr_of = spkt.hdr.get_current_of()
        if (not spkt.hdr.is_last_path_of() or
                (curr_of.ingress_if and curr_of.egress_if)):
            logging.warning("Trying to terminate packet that is not at the " +
                            "end of a segment.")
            return
        # Forward packet to destination.
        if ptype == PT.PATH_MGMT:
            addr = self.topology.path_servers[0].addr
            port = SCION_UDP_PORT
        else:
            addr = spkt.hdr.dst_addr.host_addr
            port = SCION_UDP_EH_DATA_PORT
        self.send(spkt, addr, port)
    
    def handle_ingress_xovr(self, spkt):
        """
        Main entry for crossover points at the ingress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        # Preconditions
        assert curr_of.is_xovr()

        if curr_iof.info == OFT.SHORTCUT:
            self.ingress_shortcut_xovr(spkt)
        elif curr_iof.info in [OFT.INTRA_ISD_PEER, OFT.INTER_ISD_PEER]:
            self.ingress_peer_xovr(spkt)
        elif curr_iof.info == OFT.CORE:
            self.ingress_core_xovr(spkt)
        else:
            logging.error("Current Info OF invalid.")
    
    def ingress_shortcut_xovr(self, spkt):
        """
        Handles the crossover point for shortcut paths at the ingress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        # Preconditions
        assert curr_iof.info == OFT.SHORTCUT
        assert spkt.hdr.is_on_up_path()

        if not self.verify_of(curr_of, spkt.hdr.get_relative_of(1),
                              curr_iof.timestamp):
            logging.error("Verification of current OF failed. Dropping packet.")
            return

        # Switch to next path segment.
        spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p + 16
        spkt.hdr.increase_of(4)
        # Handle on-path shortcut case.
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        if not curr_of.egress_if and spkt.hdr.is_last_path_of():
            if not self.verify_of(curr_of, spkt.hdr.get_relative_of(-1),
                                  curr_iof.timestamp):
                logging.error("Verification of current OF failed. " +
                              "Dropping packet.")
                return
            self.terminate(spkt, PT.DATA)
        else:
            self.send(spkt, self.ifid2addr[curr_of.egress_if])
            
    def ingress_peer_xovr(self, spkt):
        """
        Handles the crossover point for peer paths at the ingress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        # Preconditions
        assert curr_iof.info in [OFT.INTRA_ISD_PEER, OFT.INTER_ISD_PEER]
        
        on_up_path = spkt.hdr.is_on_up_path()
        if on_up_path:
            prev_of = spkt.hdr.get_relative_of(2)
            fwd_if = spkt.hdr.get_relative_of(1).ingress_if
        else:
            prev_of = spkt.hdr.get_relative_of(1)
            fwd_if = spkt.hdr.get_relative_of(1).egress_if

        if not self.verify_of(curr_of, prev_of, curr_iof.timestamp):
            logging.error("Verification of current OF failed. Dropping packet.")
            return
        spkt.hdr.increase_of(1)

        if spkt.hdr.is_last_path_of():
            assert not on_up_path
            self.terminate(spkt, PT.DATA)
        else:
            self.send(spkt, self.ifid2addr[fwd_if])

    def ingress_core_xovr(self, spkt):
        """
        Handles the crossover point for core paths at the ingress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        # Preconditions
        assert curr_iof.info == OFT.CORE

        if spkt.hdr.is_on_up_path():
            prev_of = None
        else:
            prev_of = spkt.hdr.get_relative_of(-1)
        if not self.verify_of(curr_of, prev_of, curr_iof.timestamp):
            logging.error("Verification of current OF failed. Dropping packet.")
            return

        if spkt.hdr.is_last_path_of():
            self.terminate(spkt, PT.DATA)
        else:
            # Switch to next path segment.
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p + 8
            spkt.hdr.increase_of(2)
            curr_of = spkt.hdr.get_current_of()
            if spkt.hdr.is_on_up_path():
                self.send(spkt, self.ifid2addr[curr_of.ingress_if])
            else:
                self.send(spkt, self.ifid2addr[curr_of.egress_if])
    
    def ingress_normal_forward(self, spkt):
        """
        Handles normal forwarding of packets at the ingress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        if spkt.hdr.is_on_up_path():
            fwd_if = curr_of.ingress_if
            prev_of = spkt.hdr.get_relative_of(1)
        else:
            fwd_if = curr_of.egress_if
            prev_of = spkt.hdr.get_relative_of(-1)

        if not self.verify_of(curr_of, prev_of, curr_iof.timestamp):
            logging.error("Verification of current OF failed. Dropping packet.")
            return

        if not fwd_if and spkt.hdr.is_last_path_of():
            self.terminate(spkt, PT.DATA)
        else:
            self.send(spkt, self.ifid2addr[fwd_if])
    
    def handle_egress_xovr(self, spkt):
        """
        Main entry for crossover points at the egress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        # Preconditions
        assert curr_of.is_xovr()

        if curr_iof.info == OFT.SHORTCUT:
            self.egress_shortcut_xovr(spkt)
        elif curr_iof.info in [OFT.INTRA_ISD_PEER, OFT.INTER_ISD_PEER]:
            self.egress_peer_xovr(spkt)
        elif curr_iof.info == OFT.CORE:
            self.egress_core_xovr(spkt)
        else:
            logging.error("Current Info OF invalid.")
    
    def egress_shortcut_xovr(self, spkt):
        """
        Handles the crossover point for shortcut paths at the egress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        # Preconditions
        assert curr_of.is_xovr()
        assert curr_iof.info == OFT.SHORTCUT
        assert not spkt.hdr.is_on_up_path()

        self.egress_normal_forward(spkt)

    def egress_peer_xovr(self, spkt):
        """
        Handles the crossover point for peer paths at the egress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        # Preconditions
        assert curr_of.is_xovr()
        assert curr_iof.info in [OFT.INTRA_ISD_PEER, OFT.INTER_ISD_PEER]

        if spkt.hdr.is_on_up_path():
            if not self.verify_of(curr_of, spkt.hdr.get_relative_of(-1),
                                  curr_iof.timestamp):
                logging.error("Verification of current OF failed. " +
                              "Dropping packet.")
                return
            # Switch to next path-segment
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p + 16
            spkt.hdr.increase_of(4)
        else:
            if not self.verify_of(curr_of, spkt.hdr.get_relative_of(-2),
                                  curr_iof.timestamp):
                logging.error("Verification of current OF failed. " +
                              "Dropping packet.")
                return
            spkt.hdr.increase_of(1)

        self.send(spkt, self.interface.to_addr, self.interface.to_udp_port)

    def egress_core_xovr(self, spkt):
        """
        Handles the crossover point for core paths at the egress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        # Preconditions
        assert curr_of.is_xovr()
        assert curr_iof.info == OFT.CORE

        if not spkt.hdr.is_on_up_path():
            prev_of = None
        else:
            prev_of = spkt.hdr.get_relative_of(1)
        if not self.verify_of(curr_of, prev_of, curr_iof.timestamp):
            logging.error("Verification of current OF failed. Dropping packet.")
            return

        spkt.hdr.increase_of(1)
        self.send(spkt, self.interface.to_addr, self.interface.to_udp_port)

    def egress_normal_forward(self, spkt):
        """
        Handles normal forwarding of packets at the egress router.
        """
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        if spkt.hdr.is_on_up_path():
            prev_of = spkt.hdr.get_relative_of(1)
        else:
            prev_of = spkt.hdr.get_relative_of(-1)

        if not self.verify_of(curr_of, prev_of, curr_iof.timestamp):
            logging.error("Verification of current OF failed. Dropping packet.")
            return

        spkt.hdr.increase_of(1)
        self.send(spkt, self.interface.to_addr, self.interface.to_udp_port)

    def forward_packet(self, spkt, from_local_ad):
        """
        Main entry point for data packet forwarding.

        :param spkt: The SCION Packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param from_local_ad: Whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        curr_of = spkt.hdr.get_current_of()
        # Ingress entry point.
        if not from_local_ad:
            if curr_of.info == OFT.XOVR_POINT:
                self.handle_ingress_xovr(spkt)
            else:
                self.ingress_normal_forward(spkt)
        else:
            if curr_of.info == OFT.XOVR_POINT:
                self.handle_egress_xovr(spkt)
            else:
                self.egress_normal_forward(spkt)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.

        :param packet: The incoming packet to handle.
        :type packet: bytes
        :param sender: Tuple of sender IP, port.
        :type sender: Tuple
        :param from_local_socket: True, if the packet was received on the local
                                  socket.
        :type from_local_socket: bool

        .. note::
           `sender` is not used in this function at the moment.
        """
        from_local_ad = from_local_socket
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.DATA:
            self.forward_packet(spkt, from_local_ad)
        elif ptype == PT.IFID_PKT and not from_local_ad:
            self.process_ifid_request(packet)
        elif ptype == PT.BEACON:
            self.process_pcb(packet, from_local_ad)
        elif ptype in [PT.CERT_CHAIN_REQ, PT.CERT_CHAIN_REP, PT.TRC_REQ,
                       PT.TRC_REP]:
            self.relay_cert_server_packet(spkt, from_local_ad)
        elif ptype == PT.PATH_MGMT:
            self.process_path_mgmt_packet(spkt, from_local_ad)
        else:
            logging.error("Unknown packet type.")

def main():
    """
    Initializes and starts router.
    """
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('router_id', help='Router identifier')
    parser.add_argument('topo_file', help='Topology file')
    parser.add_argument('conf_file', help='AD configuration file')
    parser.add_argument('log_file', help='Log file')
    args = parser.parse_args()
    init_logging(args.log_file)

    router = Router(args.router_id, args.topo_file, args.conf_file)

    logging.info("Started: %s", datetime.datetime.now())
    router.run()

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
