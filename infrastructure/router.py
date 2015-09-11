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
from external.expiring_dict import ExpiringDict
"""
:mod:`router` --- SCION edge router
===========================================
"""
# Stdlib
import argparse
import datetime
import logging
import random
import socket
import sys
import threading
import time
from collections import defaultdict

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.symcrypto import get_roundkey_cache, verify_of_mac
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    EXP_TIME_UNIT,
    IFID_PKT_TOUT,
    PATH_SERVICE,
    ROUTER_SERVICE,
    SCION_UDP_EH_DATA_PORT,
    SCION_UDP_PORT,
)
from lib.errors import (
    SCIONBaseError,
    SCIONBaseException,
    SCIONServiceLookupError,
)
from lib.log import init_logging, log_exception
from lib.packet.host_addr import ADDR_SVC_TYPE
from lib.packet.ext_hdr import ExtensionClass
from lib.packet.ext.traceroute import TracerouteExt, traceroute_ext_handler
from lib.packet.opaque_field import (
    HopOpaqueField as HOF,
    OpaqueFieldType as OFT,
)
from lib.packet.path_mgmt import (
    PathMgmtPacket,
    PathMgmtType as PMT,
    RevocationInfo,
    IFStateRequest,)
from lib.packet.pcb import PathConstructionBeacon
from lib.packet.scion import (
    IFIDPacket,
    PacketType as PT,
    SCIONPacket,
    get_type,
)
from lib.packet.scion_addr import ISD_AD, SCIONAddr
from lib.thread import thread_safety_net
from lib.util import handle_signals, SCIONTime, sleep_interval, start_thread

MAX_EXT = 4  # Maximum number of hop-by-hop extensions processed by router.


class SCIONOFVerificationError(SCIONBaseError):
    """
    Opaque field MAC verification error.
    """
    pass


class SCIONOFExpiredError(SCIONBaseError):
    """
    Opaque field expired error.
    """
    pass


class SCIONPacketHeaderCorruptedError(SCIONBaseError):
    """
    Packet header is in an invalid state.
    """
    pass


class SCIONInterfaceDownException(SCIONBaseException):
    """
    The interface to forward the packet to is down.
    """
    def __init__(self, if_id):
        super().__init__()
        self.if_id = if_id


class InterfaceState(object):
    """
    Class to store the interface state of the other edge routers, along with
    the corresponding current revocation token and proof.
    """
    def __init__(self):
        self.is_active = True
        self.rev_token = None
        self.proof = None

    def update(self, ifstate):
        """
        Updates the interface state.

        :param ifstate: IFStateInfo object sent by the BS.
        :type ifstate: :class: `lib.packet.path_mgmt.IFStateInfo`
        """
        self.is_active = bool(ifstate.state)
        self.rev_token = ifstate.rev_info.rev_token
        self.proof = ifstate.rev_info.proof


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
    """
    FWD_REVOCATION_TIMEOUT = 5
    IFSTATE_REQ_INTERVAL = 30

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
        :ivar pre_ext_handlers: a map of extension header types to handlers for
                            those extensions that execute before routing.
        :type pre_ext_handlers: dict
        :ivar post_ext_handlers: a map of extension header types to handlers for
                             those extensions that execute after routing.
        :type post_ext_handlers: dict
        :param is_sim: running in simulator
        :type is_sim: bool
        """
        SCIONElement.__init__(self, ROUTER_SERVICE, topo_file,
                              server_id=router_id, config_file=config_file,
                              is_sim=is_sim)
        self.interface = None
        for edge_router in self.topology.get_all_edge_routers():
            if edge_router.addr == self.addr.host_addr:
                self.interface = edge_router.interface
                break
        assert self.interface is not None
        logging.info("Interface: %s", self.interface.__dict__)
        self.of_gen_key = get_roundkey_cache(self.config.master_ad_key)
        self.if_states = defaultdict(InterfaceState)
        self.revocations = ExpiringDict(1000, self.FWD_REVOCATION_TIMEOUT)
        self.pre_ext_handlers = pre_ext_handlers or {}
        self.post_ext_handlers = post_ext_handlers or {}
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
        ifstate_req_thread = threading.Thread(
            target=thread_safety_net, args=(self.request_ifstates,),
            name="ER.request_ifstates", daemon=True)
        threading.Timer(5, start_thread, (ifstate_req_thread,)).start()
        SCIONElement.run(self)

    def send(self, spkt, addr, port=SCION_UDP_PORT, use_local_socket=True):
        """
        Send a spkt to addr (class of that object must implement
        __str__ which returns IPv4 addr) using port and local or remote
        socket.

        :param spkt: The packet to send.
        :type spkt: :class:`lib.spkt.SCIONspkt`
        :param addr: The address of the next hop.
        :type addr: :class:`IPv4Adress`
        :param port: The port number of the next hop.
        :type port: int
        :param use_local_socket: whether to use the local socket (as opposed to
                                 a remote socket).
        :type use_local_socket: bool
        """
        self.handle_extensions(spkt, False)
        if use_local_socket:
            super().send(spkt, addr, port)
        else:
            self._remote_socket.sendto(
                spkt.pack(), (str(addr), port))

    def handle_extensions(self, spkt, pre_routing_phase):
        """
        Handle SCION Packet extensions. Handlers can be defined for pre- and
        post-routing.

        :param spkt:
        :type spkt:
        :param pre_routing_phase:
        :type pre_routing_phase:
        """
        if pre_routing_phase:
            handlers = self.pre_ext_handlers
        else:
            handlers = self.post_ext_handlers
        ext_type = spkt.hdr.common_hdr.next_hdr
        c = 0
        # Hop-by-hop extensions must be first (just after path), and process
        # only MAX_EXT number of them.
        while ext_type == ExtensionClass.HOP_BY_HOP and c < MAX_EXT:
            ext_hdr = spkt.hdr.extension_hdrs[c]
            ext_nr = ext_hdr.EXT_TYPE
            if ext_nr in handlers:
                handlers[ext_nr](spkt=spkt, ext=ext_hdr, conf=self.config,
                                 topo=self.topology, iface=self.interface)
            else:
                logging.debug("No handler for extension type %u", ext_nr)
            ext_type = ext_hdr.next_hdr
            c += 1
        if c >= MAX_EXT and ext_type == ExtensionClass.HOP_BY_HOP:
            logging.warning("Too many hop-by-hop extensions.")

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

    def request_ifstates(self):
        """
        Periodically request interface states from the BS.
        """
        src = SCIONAddr.from_values(self.topology.isd_id, self.topology.ad_id,
                                    self.interface.addr)
        dst_isd_ad = ISD_AD(self.topology.isd_id, self.topology.ad_id)
        ifstates_req = IFStateRequest.from_values()
        req_pkt = PathMgmtPacket.from_values(PMT.IFSTATE_REQ, ifstates_req,
                                             None, src, dst_isd_ad)
        while True:
            start_time = SCIONTime.get_time()
            logging.info("Sending IFStateRequest for IF %d")
            for bs in self.topology.beacon_servers:
                self.send(req_pkt, bs.addr)
            sleep_interval(start_time, self.IFSTATE_REQ_INTERVAL,
                           "request_ifstates")


    def process_ifid_request(self, ifid_packet):
        """
        After receiving IFID_PKT from neighboring router it is completed (by
        iface information) and passed to local BSes.

        :param ifid_packet: the IFID request packet to send.
        :type ifid_packet: :class:`lib.packet.scion.IFIDPacket`
        """
        # Forward 'alive' packet to all BSes (to inform that neighbor is alive).
        # BS must determine interface.
        ifid_packet.reply_id = self.interface.if_id
        try:
            bs_addrs = self.dns_query_topo(BEACON_SERVICE)
        except SCIONServiceLookupError as e:
            logging.error("Unable to deliver ifid packet: %s", e)
            return
        for bs_addr in bs_addrs:
            self.send(ifid_packet, bs_addr)

    def process_pcb(self, beacon, from_bs):
        """
        Depending on scenario: a) send PCB to all beacon servers, or b) to
        neighboring router.

        :param beacon: The PCB.
        :type beacon: :class:`lib.packet.pcb.PathConstructionBeacon`
        :param from_bs: True, if the beacon was received from local BS.
        :type from_bs: bool
        """
        if from_bs:
            if self.interface.if_id != beacon.pcb.get_last_pcbm().hof.egress_if:
                logging.error("Wrong interface set by BS.")
                return
            self.send(beacon, self.interface.to_addr,
                      self.interface.to_udp_port, False)
        else:
            beacon.pcb.if_id = self.interface.if_id
            try:
                bs_addr = self.dns_query_topo(BEACON_SERVICE)[0]
            except SCIONServiceLookupError as e:
                logging.error("Unable to deliver PCB: %s", e)
                return
            self.send(beacon, bs_addr)

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
            try:
                addr = self.dns_query_topo(CERTIFICATE_SERVICE)[0]
            except SCIONServiceLookupError as e:
                logging.error("Unable to deliver cert packet: %s", e)
                return
            port = SCION_UDP_PORT
        self.send(spkt, addr, port)

    def process_path_mgmt_packet(self, mgmt_pkt, from_local_ad):
        """
        Process path management packets.

        :param mgmt_pkt: The path mgmt packet.
        :type mgmt_pkt: :class:`lib.packet.path_mgmt.PathMgmtPacket`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        if mgmt_pkt.type == PMT.IFSTATE_INFO:
            # handle state update
            logging.debug("Received IFState update:\n%s", str(mgmt_pkt.payload))
            ifstates = mgmt_pkt.payload.ifstate_infos
            for ifstate in ifstates:
                self.if_states[ifstate.if_id].update(ifstate)
            return
        elif mgmt_pkt.type == PMT.REVOCATION:
            if not from_local_ad:
                # Forward to local path server if we haven't recently.
                rev_token = mgmt_pkt.payload.rev_token
                if (self.topology.path_servers and
                        rev_token not in self.revocations):
                    logging.debug("Forwarding revocation to local PS.")
                    self.revocations[rev_token] = True
                    ps = random.choice(self.topology.path_servers)
                    self.send(mgmt_pkt, ps.addr)

        if not from_local_ad and mgmt_pkt.hdr.is_last_path_of():
            if (mgmt_pkt.type == PMT.REVOCATION and
                    mgmt_pkt.hdr.dst_addr.host_addr.TYPE != ADDR_SVC_TYPE):
                self.deliver(mgmt_pkt, PT.DATA)
            else:
                self.deliver(mgmt_pkt, PT.PATH_MGMT)
        else:
            self.forward_packet(mgmt_pkt, from_local_ad)

    def send_revocation(self, spkt, if_id):
        """
        Sends an interface revocation for 'if_id' along the path in 'spkt'.
        """
        # Check that the interface is really down.
        if_state = self.if_states[if_id]
        if self.if_states[if_id].is_active:
            logging.error("Interface %d appears to be up. Not sending " +
                          "revocation." % if_id)
            return

        if not if_state.rev_token or not if_state.proof:
            logging.error("Revocation token and/or proof missing.")
            return

        rev_info = RevocationInfo.from_values(if_state.rev_token,
                                              if_state.proof)
        reversed_hdr = spkt.hdr.reversed_copy()
        src_addr = SCIONAddr.from_values(self.topology.isd_id,
                                         self.topology.ad_id,
                                         PT.PATH_MGMT)
        rev_pkt = PathMgmtPacket.from_values(PMT.REVOCATION, rev_info,
                                             reversed_hdr.path, src_addr,
                                             reversed_hdr.dst_addr)
        # Update pointers to correct values.
        rev_pkt.hdr.set_curr_iof_p(reversed_hdr.get_curr_iof_p())
        rev_pkt.hdr.set_curr_of_p(reversed_hdr.get_curr_of_p())
        logging.debug("Revocation Packet:\n%s", rev_pkt)
        self.forward_packet(rev_pkt, True)

    def deliver(self, spkt, ptype):
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
            logging.warning("Trying to deliver packet that is not at the " +
                            "end of a segment.")
            return
        # Forward packet to destination.
        if ptype == PT.PATH_MGMT:
            try:
                addr = self.dns_query_topo(PATH_SERVICE)[0]
            except SCIONServiceLookupError as e:
                logging.error("Unable to deliver path mgmt packet: %s", e)
                return
            port = SCION_UDP_PORT
        else:
            addr = spkt.hdr.dst_addr.host_addr
            port = SCION_UDP_EH_DATA_PORT
        self.send(spkt, addr, port)

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
            if not verify_of_mac(self.of_gen_key, hof, prev_hof, ts):
                raise SCIONOFVerificationError
        else:
            raise SCIONOFExpiredError

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

        if not spkt.hdr.is_on_up_path():
            raise SCIONPacketHeaderCorruptedError

        self.verify_of(curr_of, spkt.hdr.get_relative_of(1), curr_iof.timestamp)

        # Switch to next path segment.
        spkt.hdr.set_curr_iof_p(spkt.hdr.get_curr_of_p() + 2 * HOF.LEN)
        spkt.hdr.increase_curr_of_p(4)
        curr_of = spkt.hdr.get_current_of()
        curr_iof = spkt.hdr.get_current_iof()
        # Check interface availability.
        if not self.if_states[curr_of.egress_if].is_active:
            raise SCIONInterfaceDownException(curr_of.egress_if)
        # Handle on-path shortcut case.
        if not curr_of.egress_if and spkt.hdr.is_last_path_of():
            self.verify_of(curr_of, spkt.hdr.get_relative_of(-1),
                           curr_iof.timestamp)
            self.deliver(spkt, PT.DATA)
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

        self.verify_of(curr_of, prev_of, curr_iof.timestamp)
        spkt.hdr.increase_curr_of_p(1)

        # Check interface availability.
        if not self.if_states[curr_of.egress_if].is_active:
            raise SCIONInterfaceDownException(curr_of.egress_if)

        if spkt.hdr.is_last_path_of():
            self.deliver(spkt, PT.DATA)
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

        self.verify_of(curr_of, prev_of, curr_iof.timestamp)

        if spkt.hdr.is_last_path_of():
            self.deliver(spkt, PT.DATA)
        else:
            # Switch to next path segment.
            spkt.hdr.set_curr_iof_p(spkt.hdr.get_curr_of_p() + HOF.LEN)
            spkt.hdr.increase_curr_of_p(2)
            curr_of = spkt.hdr.get_current_of()
            fwd_if = (curr_of.ingress_if if spkt.hdr.is_on_up_path() else
                      curr_of.egress_if)
            # Check interface availability.
            if not self.if_states[fwd_if].is_active:
                raise SCIONInterfaceDownException(curr_of.egress_if)
            else:
                self.send(spkt, self.ifid2addr[fwd_if])

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

        self.verify_of(curr_of, prev_of, curr_iof.timestamp)

        # Check interface availability.
        if not self.if_states[fwd_if].is_active:
            raise SCIONInterfaceDownException(curr_of.egress_if)

        if not fwd_if and spkt.hdr.is_last_path_of():
            self.deliver(spkt, PT.DATA)
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

        if spkt.hdr.is_on_up_path():
            raise SCIONPacketHeaderCorruptedError

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
            self.verify_of(curr_of, spkt.hdr.get_relative_of(-1),
                           curr_iof.timestamp)
            # Switch to next path-segment
            spkt.hdr.set_curr_iof_p(spkt.hdr.get_curr_of_p() + 2 * HOF.LEN)
            spkt.hdr.increase_curr_of_p(4)
        else:
            self.verify_of(curr_of, spkt.hdr.get_relative_of(-2),
                           curr_iof.timestamp)
            spkt.hdr.increase_curr_of_p(1)

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

        self.verify_of(curr_of, prev_of, curr_iof.timestamp)

        spkt.hdr.increase_curr_of_p(1)
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

        self.verify_of(curr_of, prev_of, curr_iof.timestamp)

        spkt.hdr.increase_curr_of_p(1)
        self.send(spkt, self.interface.to_addr, self.interface.to_udp_port)

    def forward_packet(self, spkt, from_local_ad):
        """
        Main entry point for data packet forwarding.

        :param spkt: The SCION Packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param from_local_ad: Whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        try:
            curr_of = spkt.hdr.get_current_of()
            # Ingress entry point.
            if not from_local_ad:
                if curr_of.info == OFT.XOVR_POINT:
                    self.handle_ingress_xovr(spkt)
                else:
                    self.ingress_normal_forward(spkt)
            # Egress entry point.
            else:
                if curr_of.info == OFT.XOVR_POINT:
                    self.handle_egress_xovr(spkt)
                else:
                    self.egress_normal_forward(spkt)
        except SCIONOFVerificationError:
            logging.error("Dropping packet due to incorrect MAC.")
        except SCIONOFExpiredError:
            logging.error("Dropping packet due to expired OF.")
        except SCIONPacketHeaderCorruptedError:
            logging.error("Dropping packet due to invalid header state.")
        except SCIONInterfaceDownException as e:
            if get_type(spkt) == PT.DATA:
                logging.error("Interface %d is down. Issuing revocation.",
                              e.if_id)
                self.send_revocation(spkt, int(e.if_id))

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
        self.handle_extensions(spkt, True)
        if ptype == PT.DATA:
            logging.debug("Data packet entering:\n%s", spkt)
            self.forward_packet(spkt, from_local_ad)
        elif ptype == PT.IFID_PKT and not from_local_ad:
            self.process_ifid_request(IFIDPacket(packet))
        elif ptype == PT.BEACON:
            self.process_pcb(PathConstructionBeacon(packet), from_local_ad)
        elif ptype in [PT.CERT_CHAIN_REQ, PT.CERT_CHAIN_REP, PT.TRC_REQ,
                       PT.TRC_REP]:
            self.relay_cert_server_packet(spkt, from_local_ad)
        elif ptype == PT.PATH_MGMT:
            self.process_path_mgmt_packet(PathMgmtPacket(packet), from_local_ad)
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
    # Run router without extensions handling:
    # router = Router(args.router_id, args.topo_file, args.conf_file)
    # Run router with an extension handler:
    pre_handlers = {TracerouteExt.EXT_TYPE: traceroute_ext_handler}
    router = Router(args.router_id, args.topo_file, args.conf_file,
                    pre_ext_handlers=pre_handlers)

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
