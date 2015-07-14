# Copyright 2014 ETH Zurich
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
"""
:mod:`router` --- SCION edge router
===========================================
"""
# Stdlib
import datetime
import logging
import socket
import sys
import threading
import time

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.symcrypto import get_roundkey_cache, verify_of_mac
from lib.defines import SCION_UDP_PORT, SCION_UDP_EH_DATA_PORT, EXP_TIME_UNIT
from lib.log import init_logging, log_exception
from lib.packet.opaque_field import OpaqueField, OpaqueFieldType as OFT
from lib.packet.pcb import PathConstructionBeacon
from lib.packet.scion import (
    IFIDPacket,
    PacketType as PT,
    SCIONPacket,
    get_type,
)
from lib.packet.scion_addr import ISD_AD, SCIONAddr
from lib.thread import thread_safety_net
from lib.util import handle_signals, SCIONTime

IFID_PKT_TOUT = 1  # How often IFID packet is sent to neighboring router.


class NextHop(object):
    """
    Simple class for next hop representation. Object of this class corresponds
    to SCION Packet and is processed within routing context.

    :ivar addr: the next hop address.
    :type addr: str
    :ivar port: the next hop port number.
    :type port: int
    """

    def __init__(self):
        """
        Initialize an instance of the class NextHop.
        """
        self.addr = None
        self.port = SCION_UDP_PORT

    def __str__(self):
        """
        Return the next hop address and port number.

        :returns: string with next hop address and port number.
        :rtype: string
        """
        return "%s:%d" % (self.addr, self.port)


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
            target=thread_safety_net,
            args=("sync_interface", self.sync_interface),
            name="Sync Interfaces",
            daemon=True).start()
        SCIONElement.run(self)

    def send(self, packet, next_hop, use_local_socket=True):
        """
        Send a packet to next_hop.addr (class of that object must implement
        __str__ which returns IPv4 addr) using next_hop.port and local or remote
        socket.

        :param packet:
        :type packet:
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param use_local_socket: whether to use the local socket (as opposed to
                                 a remote socket).
        :type use_local_socket: bool
        """
        logging.info("Sending packet to %s", next_hop)
        self.handle_extensions(packet, next_hop, False)
        if use_local_socket:
            SCIONElement.send(self, packet, next_hop.addr, next_hop.port)
        else:
            self._remote_socket.sendto(
                packet.pack(), (str(next_hop.addr), next_hop.port))

    def handle_extensions(self, spkt, next_hop, pre_routing_phase):
        """
        Handle SCION Packet extensions. Handlers can be defined for pre- and
        post-routing. A handler takes two parameters: packet (SCIONPacket),
        next_hop (NextHop).

        :param spkt:
        :type spkt:
        :param next_hop:
        :type next_hop:
        :param pre_routing_phase:
        :type pre_routing_phase:
        """
        if pre_routing_phase:
            handlers = self.pre_ext_handlers
        else:
            handlers = self.post_ext_handlers
        ext = spkt.hdr.common_hdr.next_hdr
        l = 0
        while ext and l < len(spkt.hdr.extension_hdrs):
            if ext in handlers:
                handlers[ext](spkt, next_hop)
            ext = ext.next_ext
            l += 1
        if ext or l < len(spkt.hdr.extension_hdrs):
            logging.warning("Extensions terminated incorrectly.")

    def sync_interface(self):
        """
        Synchronize and initialize the router's interface with that of a
        neighboring router.
        """
        next_hop = NextHop()
        next_hop.addr = self.interface.to_addr
        next_hop.port = self.interface.to_udp_port
        src = SCIONAddr.from_values(self.topology.isd_id, self.topology.ad_id,
                                    self.interface.addr)
        dst_isd_ad = ISD_AD(self.interface.neighbor_isd,
                            self.interface.neighbor_ad)
        ifid_req = IFIDPacket.from_values(src, dst_isd_ad, self.interface.if_id)
        while True:
            self.send(ifid_req, next_hop, False)
            logging.info('Sending IFID_PKT to router: req_id:%d, rep_id:%d',
                         ifid_req.request_id, ifid_req.reply_id)
            time.sleep(IFID_PKT_TOUT)

    def process_ifid_request(self, packet, next_hop):
        """
        After receiving IFID_PKT from neighboring router it is completed (by
        iface information) and passed to local BSes.

        :param packet: the IFID request packet to send.
        :type packet: bytes
        :param next_hop: the next hop of the request packet.
        :type next_hop: :class:`NextHop`
        """
        logging.info('IFID_PKT received, len %u', len(packet))
        ifid_req = IFIDPacket(packet)
        # Forward 'alive' packet to all BSes (to inform that neighbor is alive).
        ifid_req.reply_id = self.interface.if_id  # BS must determine interface.
        for bs in self.topology.beacon_servers:
            next_hop.addr = bs.addr
            self.send(ifid_req, next_hop)

    def process_pcb(self, packet, next_hop, from_bs):
        """
        Depending on scenario: a) send PCB to all beacon servers, or b) to
        neighboring router.

        :param packet:
        :type packet:
        :param next_hop:
        :type next_hop:
        :param from_bs:
        :type from_bs:
        """
        beacon = PathConstructionBeacon(packet)
        if from_bs:
            if self.interface.if_id != beacon.pcb.get_last_pcbm().hof.egress_if:
                logging.error("Wrong interface set by BS.")
                return
            next_hop.addr = self.interface.to_addr
            next_hop.port = self.interface.to_udp_port
            self.send(beacon, next_hop, False)
        else:
            # TODO Multiple BS scenario
            beacon.pcb.if_id = self.interface.if_id
            next_hop.addr = self.topology.beacon_servers[0].addr
            self.send(beacon, next_hop)

    def relay_cert_server_packet(self, spkt, next_hop, from_local_ad):
        """
        Relay packets for certificate servers.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        if from_local_ad:
            next_hop.addr = self.interface.to_addr
            next_hop.port = self.interface.to_udp_port
        else:
            # TODO Multiple CS scenario
            next_hop.addr = self.topology.certificate_servers[0].addr
        self.send(spkt, next_hop)

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

    def normal_forward(self, spkt, next_hop, from_local_ad, ptype):
        """
        Process normal forwarding.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        :param ptype: the type of the packet.
        :type ptype: :class:`lib.packet.scion.PacketType`
        """
        curr_hof = spkt.hdr.get_current_of()
        prev_hof = None
        is_on_up_path = spkt.hdr.is_on_up_path()
        timestamp = spkt.hdr.get_current_iof().timestamp
        if is_on_up_path:
            iface = curr_hof.ingress_if
            prev_hof = spkt.hdr.get_relative_of(1)
        else:
            iface = curr_hof.egress_if
            if spkt.hdr.get_relative_of(-1).is_regular():
                prev_hof = spkt.hdr.get_relative_of(-1)
        if from_local_ad:
            if iface == self.interface.if_id:
                next_hop.addr = self.interface.to_addr
                next_hop.port = self.interface.to_udp_port
                spkt.hdr.increase_of(1)
                if self.verify_of(curr_hof, prev_hof, timestamp):
                    self.send(spkt, next_hop, False)
            else:
                logging.error("1 interface mismatch %u != %u", iface,
                              self.interface.if_id)
        else:
            if iface:
                next_hop.addr = self.ifid2addr[iface]
            elif ptype in [PT.PATH_MGMT, PT.PATH_MGMT]:
                next_hop.addr = self.topology.path_servers[0].addr
            else:  # last opaque field on the path, send the packet to the dst
                next_hop.addr = spkt.hdr.dst_addr.host_addr
                next_hop.port = SCION_UDP_EH_DATA_PORT  # data packet to endhost
            if self.verify_of(curr_hof, prev_hof, timestamp):
                self.send(spkt, next_hop)
        logging.debug("normal_forward()")

    def crossover_forward(self, spkt, next_hop, info):
        """
        Process crossover forwarding.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param info: the type of opaque field.
        :type info: :class:`lib.packet.opaque_field.OpaqueFieldType`
        """
        logging.debug("crossover_forward()")
        curr_hof = spkt.hdr.get_current_of()
        prev_hof = None
        is_on_up_path = spkt.hdr.is_on_up_path()
        timestamp = spkt.hdr.get_current_iof().timestamp
        if info == OFT.TDC_XOVR:
            if not is_on_up_path:
                prev_hof = spkt.hdr.get_relative_of(-1)
            if self.verify_of(curr_hof, prev_hof, timestamp):
                spkt.hdr.increase_of(1)
                next_iof = spkt.hdr.get_current_of()
                opaque_field = spkt.hdr.get_relative_of(1)
                if next_iof.up_flag:  # TODO replace by get_first_hop
                    next_hop.addr = self.ifid2addr[opaque_field.ingress_if]
                else:
                    next_hop.addr = self.ifid2addr[opaque_field.egress_if]
                logging.debug("send() here, find next hop0.")
                self.send(spkt, next_hop)
        elif info == OFT.NON_TDC_XOVR:
            prev_hof = spkt.hdr.get_relative_of(1)
            if self.verify_of(curr_hof, prev_hof, timestamp):
                spkt.hdr.increase_of(2)
                opaque_field = spkt.hdr.get_relative_of(2)
                if opaque_field.egress_if:
                    next_hop.addr = self.ifid2addr[opaque_field.egress_if]
                else:  # Send to endhost (on-path case), TODO: check length
                    spkt.hdr.common_hdr.curr_iof_p = \
                        spkt.hdr.common_hdr.curr_of_p
                    timestamp = spkt.hdr.get_current_iof().timestamp
                    prev_hof = spkt.hdr.get_relative_of(1)
                    if not self.verify_of(opaque_field, prev_hof, timestamp):
                        return
                    next_hop.addr = spkt.hdr.dst_addr.host_addr
                    next_hop.port = SCION_UDP_EH_DATA_PORT
                logging.debug("send() here, find next hop1")
                self.send(spkt, next_hop)
        elif info == OFT.INPATH_XOVR:  # TODO: implement that case
            if self.verify_of(curr_hof, prev_hof, timestamp):
                is_regular = True
                while is_regular:
                    spkt.hdr.increase_of(2)
                    is_regular = spkt.hdr.get_current_of().is_regular()
                spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
                logging.debug("TODO send() here, find next hop2")
        elif info == OFT.INTRATD_PEER or info == OFT.INTERTD_PEER:
            spkt.hdr.increase_of(1)
            prev_hof = spkt.hdr.get_relative_of(1)
            if self.verify_of(curr_hof, prev_hof, timestamp):
                next_hop.addr = (
                    self.ifid2addr[spkt.hdr.get_current_of().ingress_if])
                logging.debug("send() here, next: %s", next_hop)
                self.send(spkt, next_hop)
        else:
            logging.warning("Unknown case %u", info)

    def forward_packet(self, spkt, next_hop, from_local_ad, ptype):
        """
        Forward packet based on the current opaque field.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        :param ptype: the type of the packet.
        :type ptype: :class:`lib.packet.scion.PacketType`
        """
        new_segment = False
        while not spkt.hdr.get_current_of().is_regular():
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
            spkt.hdr.increase_of(1)
            new_segment = True
        while spkt.hdr.get_current_of().is_continue():
            spkt.hdr.increase_of(1)
        info = spkt.hdr.get_current_iof().info
        curr_iof_p = spkt.hdr.common_hdr.curr_iof_p
        # Case: peer path and first opaque field of a down path. We need to
        # increase opaque field pointer as that first opaque field is used for
        # MAC verification only.
        if (not spkt.hdr.is_on_up_path() and
                info in [OFT.INTRATD_PEER, OFT.INTERTD_PEER] and
                spkt.hdr.common_hdr.curr_of_p == curr_iof_p + OpaqueField.LEN):
            spkt.hdr.increase_of(1)
        if (spkt.hdr.get_current_of().info == OFT.LAST_OF and
                not spkt.hdr.is_last_path_of() and not new_segment):
            self.crossover_forward(spkt, next_hop, info)
        else:
            self.normal_forward(spkt, next_hop, from_local_ad, ptype)

    def write_to_egress_iface(self, spkt, next_hop):
        """
        Forward packet to neighboring router.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`

        .. warning::
           Long time ago it was decided that router here does not verify MAC of
           OF, as it is assumed that local router (which forwarded traffic here)
           just verified it. Should we revise that?
        """
        of_info = spkt.hdr.get_current_of().info
        if of_info == OFT.TDC_XOVR:
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
            spkt.hdr.increase_of(1)
        elif of_info == OFT.NON_TDC_XOVR:
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
            spkt.hdr.increase_of(2)
        spkt.hdr.increase_of(1)
        iof_info = spkt.hdr.get_current_iof().info
        if iof_info in [OFT.INTRATD_PEER, OFT.INTERTD_PEER]:
            if spkt.hdr.is_on_up_path():
                if spkt.hdr.get_relative_of(1).info in [OFT.INTRATD_PEER,
                                                        OFT.INTERTD_PEER]:
                    spkt.hdr.increase_of(1)
            else:
                if spkt.hdr.get_current_of().info == OFT.LAST_OF:
                    spkt.hdr.increase_of(1)
        next_hop.addr = self.interface.to_addr
        next_hop.port = self.interface.to_udp_port
        logging.debug("sending to dst6 %s", next_hop)
        self.send(spkt, next_hop, False)

    def process_packet(self, spkt, next_hop, from_local_ad, ptype):
        """
        Inspect current opaque fields and decides on forwarding type.

        :param spkt: the SCION packet to process.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        :param ptype: the type of the packet.
        :type ptype: :class:`lib.packet.scion.PacketType`
        """
        if from_local_ad:
            self.write_to_egress_iface(spkt, next_hop)
        else:
            self.forward_packet(spkt, next_hop, from_local_ad, ptype)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.

        :param packet: the incoming packet to handle.
        :type packet: SCIONPacket
        :param sender:
        :type sender:
        :param from_local_socket: whether the request is coming from a local
                                  socket.
        :type from_local_socket: bool

        .. note::
           `sender` is not used in this function at the moment.
        """
        from_local_ad = from_local_socket
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        next_hop = NextHop()
        self.handle_extensions(spkt, next_hop, True)
        if ptype == PT.IFID_PKT and not from_local_ad:
            self.process_ifid_request(packet, next_hop)
        elif ptype == PT.BEACON:
            self.process_pcb(packet, next_hop, from_local_ad)
        elif ptype in [PT.CERT_CHAIN_REQ, PT.CERT_CHAIN_REP, PT.TRC_REQ,
                       PT.TRC_REP]:
            self.relay_cert_server_packet(spkt, next_hop, from_local_ad)
        else:
            if ptype == PT.DATA:
                logging.debug("DATA type %s, %s", ptype, spkt)
            self.process_packet(spkt, next_hop, from_local_ad, ptype)


def main():
    """
    Initializes and starts router.
    """
    init_logging()
    handle_signals()
    if len(sys.argv) != 4:
        logging.error("run: %s router_id topo_file conf_file", sys.argv[0])
        sys.exit()

    router = Router(*sys.argv[1:])

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
