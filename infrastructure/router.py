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
"""
:mod:`router` --- SCION edge router
===========================================
"""
# Stdlib
import argparse
import copy
import datetime
import logging
import sys
import threading
import time
import zlib
from collections import defaultdict

# SCION
from external.expiring_dict import ExpiringDict
from infrastructure.scion_elem import SCIONElement
from lib.crypto.symcrypto import get_roundkey_cache, verify_of_mac
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    EXP_TIME_UNIT,
    IFID_PKT_TOUT,
    L4_UDP,
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
from lib.packet.ext.traceroute import TracerouteExt, traceroute_ext_handler
from lib.packet.path_mgmt import (
    RevocationInfo,
    IFStateRequest,
)
from lib.packet.scion import (
    IFIDPayload,
    PacketType as PT,
    SCIONL4Packet,
)
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import (
    AddrType,
    ExtensionClass,
    IFIDType,
    OpaqueFieldType as OFT,
    PCBType,
    PathMgmtType as PMT,
    PayloadClass,
)
from lib.util import handle_signals, SCIONTime, sleep_interval


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

    def update(self, ifstate):
        """
        Updates the interface state.

        :param ifstate: IFStateInfo object sent by the BS.
        :type ifstate: :class: `lib.packet.path_mgmt.IFStateInfo`
        """
        assert isinstance(ifstate.rev_info.rev_token, bytes)
        self.is_active = bool(ifstate.state)
        self.rev_token = ifstate.rev_info.rev_token


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
        super().__init__(ROUTER_SERVICE, topo_file, server_id=router_id,
                         config_file=config_file, is_sim=is_sim)
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

        self.PLD_CLASS_MAP = {
            PayloadClass.PCB: {PCBType.SEGMENT: self.process_pcb},
            PayloadClass.IFID: {IFIDType.PAYLOAD: self.process_ifid_request},
            PayloadClass.CERT: defaultdict(
                lambda: self.relay_cert_server_packet),
            PayloadClass.PATH: defaultdict(
                lambda: self.process_path_mgmt_packet),
        }

        if not is_sim:
            self._remote_sock = UDPSocket(
                bind=(str(self.interface.addr), self.interface.udp_port),
                addr_type=AddrType.IPV4,
            )
            self._socks.add(self._remote_sock)
            logging.info("IP %s:%d", self.interface.addr,
                         self.interface.udp_port)

    def run(self):
        """
        Run the router threads.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.sync_interface,),
            name="ER.sync_interface", daemon=True).start()
        threading.Thread(
            target=thread_safety_net, args=(self.request_ifstates,),
            name="ER.request_ifstates", daemon=True).start()
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
            self._remote_sock.send(spkt.pack(), (str(addr), port))

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
        # Hop-by-hop extensions must be first (just after path), and process
        # only MAX_EXT number of them.
        for i, ext_hdr in enumerate(spkt.ext_hdrs):
            if ext_hdr.EXT_CLASS != ExtensionClass.HOP_BY_HOP:
                break
            if i >= MAX_EXT:
                logging.error("Too many hop-by-hop extensions.")
                return False
            handler = handlers.get(ext_hdr.EXT_TYPE)
            if not handler:
                logging.warning("No handler for extension type %u",
                                ext_hdr.EXT_TYPE)
                continue
            handler(spkt=spkt, ext=ext_hdr, conf=self.config,
                    topo=self.topology, iface=self.interface)
        return False

    def sync_interface(self):
        """
        Synchronize and initialize the router's interface with that of a
        neighboring router.
        """
        ifid_pld = IFIDPayload.from_values(self.interface.if_id)
        pkt = self._build_packet(
            PT.BEACON, dst_isd=self.interface.neighbor_isd,
            dst_ad=self.interface.neighbor_ad, payload=ifid_pld)
        while True:
            self.send(pkt, self.interface.to_addr,
                      self.interface.to_udp_port, False)
            time.sleep(IFID_PKT_TOUT)

    def request_ifstates(self):
        """
        Periodically request interface states from the BS.
        """
        ifstates_req = IFStateRequest.from_values()
        req_pkt = self._build_packet(payload=ifstates_req)
        while True:
            start_time = SCIONTime.get_time()
            logging.info("Sending IFStateRequest for all interfaces.")
            for bs in self.topology.beacon_servers:
                req_pkt.addrs.dst_addr = bs.addr
                self.send(req_pkt, bs.addr)
            sleep_interval(start_time, self.IFSTATE_REQ_INTERVAL,
                           "request_ifstates")

    def process_ifid_request(self, pkt, from_local):
        """
        After receiving IFID_PKT from neighboring router it is completed (by
        iface information) and passed to local BSes.

        :param ifid_packet: the IFID request packet to send.
        :type ifid_packet: :class:`lib.packet.scion.IFIDPacket`
        """
        if from_local:
            logging.error("Received IFID packet from local AS, dropping")
            return
        ifid_pld = pkt.get_payload()
        # Forward 'alive' packet to all BSes (to inform that neighbor is alive).
        # BS must determine interface.
        ifid_pld.reply_id = self.interface.if_id
        try:
            bs_addrs = self.dns_query_topo(BEACON_SERVICE)
        except SCIONServiceLookupError as e:
            logging.error("Unable to deliver ifid packet: %s", e)
            return
        for bs_addr in bs_addrs:
            self.send(pkt, bs_addr)

    def get_srv_addr(self, service, pkt):
        """
        For a given service return a server address. Guarantee, that all packets
        from the same source to a given service are sent to the same server.

        :param str service: Service to query for.
        :type pkt: :class:`lib.packet.scion.SCIONBasePacket`

        """
        addrs = self.dns_query_topo(service)
        addrs.sort()  # To not rely on order of DNS replies.
        return addrs[zlib.crc32(pkt.addrs.pack()) % len(addrs)]

    def process_pcb(self, pkt, from_bs):
        """
        Depending on scenario: a) send PCB to a local beacon server, or b) to
        neighboring router.

        :param beacon: The PCB.
        :type beacon: :class:`lib.packet.pcb.PathConstructionBeacon`
        :param from_bs: True, if the beacon was received from local BS.
        :type from_bs: bool
        """
        pcb = pkt.get_payload()
        if from_bs:
            if self.interface.if_id != pcb.get_last_pcbm().hof.egress_if:
                logging.error("Wrong interface set by BS.")
                return
            self.send(pkt, self.interface.to_addr, self.interface.to_udp_port,
                      False)
        else:
            pcb.if_id = self.interface.if_id
            try:
                bs_addr = self.get_srv_addr(BEACON_SERVICE, pkt)
            except SCIONServiceLookupError as e:
                logging.error("Unable to deliver PCB: %s", e)
                return
            self.send(pkt, bs_addr)

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
                addr = self.get_srv_addr(CERTIFICATE_SERVICE, spkt)
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
        payload = mgmt_pkt.get_payload()
        if payload.PAYLOAD_TYPE == PMT.IFSTATE_INFO:
            # handle state update
            logging.debug("Received IFState update:\n%s",
                          str(mgmt_pkt.get_payload()))
            for ifstate in payload.ifstate_infos:
                self.if_states[ifstate.if_id].update(ifstate)
            return
        elif payload.PAYLOAD_TYPE == PMT.REVOCATION:
            if not from_local_ad:
                # Forward to local path server if we haven't recently.
                rev_token = payload.rev_token
                if (self.topology.path_servers and
                        rev_token not in self.revocations):
                    logging.debug("Forwarding revocation to local PS.")
                    self.revocations[rev_token] = True
                    try:
                        ps = self.get_srv_addr(PATH_SERVICE, mgmt_pkt)
                    except SCIONServiceLookupError:
                        logging.error("No local PS to forward revocation to.")
                        return
                    self.send(mgmt_pkt, ps.addr)
        if not from_local_ad and mgmt_pkt.path.is_last_path_hof():
            self.deliver(mgmt_pkt, PT.PATH_MGMT)
        else:
            self.forward_packet(mgmt_pkt, from_local_ad)

    def send_revocation(self, spkt, if_id):
        """
        Sends an interface revocation for 'if_id' along the path in 'spkt'.
        """
        # Only issue revocations in response to data packets.
        # TODO(shitz): Extend this to all packets containing a path
        # (i.e., path_req).
        # if get_type(spkt) != PT.DATA:
        #    return
        logging.info("Interface %d is down. Issuing revocation.", if_id)
        # Check that the interface is really down.
        if_state = self.if_states[if_id]
        if self.if_states[if_id].is_active:
            logging.error("Interface %d appears to be up. Not sending " +
                          "revocation." % if_id)
            return

        assert if_state.rev_token, "Revocation token missing."

        rev_info = RevocationInfo.from_values(if_state.rev_token)
        rev_pkt = copy.deepcopy(spkt)
        rev_pkt.reverse()
        rev_pkt.set_payload(rev_info)
        rev_pkt.addrs.src_addr = PT.PATH_MGMT
        logging.debug("Revocation Packet:\n%s", rev_pkt)
        self.forward_packet(rev_pkt, True)

    def _revoke_if_down(self, if_id, spkt):
        """
        Checks if an interface is down and if yes issues a revocation.
        """
        if not self.if_states[if_id].is_active:
            self.send_revocation(spkt, if_id)
            raise SCIONInterfaceDownException(if_id)

    def deliver(self, spkt, ptype):
        """
        Forwards the packet to the end destination within the current AD.

        :param spkt: The SCION Packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param ptype: The packet type.
        :type ptype: int
        """
        path = spkt.path
        curr_hof = path.get_hof()
        if (not path.is_last_path_hof() or
                (curr_hof.ingress_if and curr_hof.egress_if)):
            logging.error("Trying to deliver packet that is not at the " +
                          "end of a segment:\n%s", spkt)
            return
        # Forward packet to destination.
        addr = spkt.addrs.dst_addr
        if ptype == PT.PATH_MGMT:
            # FIXME(PSz): that should be changed when replies are send as
            # standard data packets.
            if spkt.addrs.dst_addr.TYPE == AddrType.SVC:
                # Send request to any path server.
                try:
                    addr = self.get_srv_addr(PATH_SERVICE, spkt)
                except SCIONServiceLookupError as e:
                    logging.error("Unable to deliver path mgmt packet: %s", e)
                    return
            port = SCION_UDP_PORT
        elif spkt._l4_proto == L4_UDP:
            port = spkt.l4_hdr.dst_port
        else:
            port = SCION_UDP_EH_DATA_PORT
        self.send(spkt, addr, port)

    def verify_hof(self, path, ingress=True):
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
        ts = path.get_iof().timestamp
        hof = path.get_hof()
        prev_hof = path.get_hof_ver(ingress=ingress)
        if int(SCIONTime.get_time()) <= ts + hof.exp_time * EXP_TIME_UNIT:
            if not verify_of_mac(self.of_gen_key, hof, prev_hof, ts):
                raise SCIONOFVerificationError(hof, prev_hof)
        else:
            raise SCIONOFExpiredError(hof)

    def handle_ingress_xovr(self, spkt):
        """
        Main entry for crossover points at the ingress router.
        """
        path = spkt.path
        curr_hof = path.get_hof()
        curr_iof = path.get_iof()
        # Preconditions
        assert curr_hof.is_xovr()

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
        path = spkt.path
        curr_iof = path.get_iof()
        # Preconditions
        assert curr_iof.info == OFT.SHORTCUT
        if not path.is_on_up_path():
            raise SCIONPacketHeaderCorruptedError

        self.verify_hof(path)
        path.next_segment()
        # Handle on-path shortcut case.
        curr_iof = path.get_iof()
        curr_hof = path.get_hof()
        self._revoke_if_down(curr_hof.egress_if, spkt)
        if not curr_hof.egress_if and path.is_last_path_hof():
            self.verify_hof(path)
            self.deliver(spkt, PT.DATA)
        else:
            self.send(spkt, self.ifid2addr[curr_hof.egress_if])

    def ingress_peer_xovr(self, spkt):
        """
        Handles the crossover point for peer paths at the ingress router.
        """
        path = spkt.path
        curr_iof = path.get_iof()
        # Preconditions
        assert curr_iof.info in [OFT.INTRA_ISD_PEER, OFT.INTER_ISD_PEER]

        self.verify_hof(path)
        path.inc_hof_idx()
        fwd_if = path.get_fwd_if()
        # Check interface availability.
        self._revoke_if_down(fwd_if, spkt)
        if path.is_last_path_hof():
            self.deliver(spkt, PT.DATA)
        else:
            self.send(spkt, self.ifid2addr[path.get_fwd_if()])

    def ingress_core_xovr(self, spkt):
        """
        Handles the crossover point for core paths at the ingress router.
        """
        path = spkt.path
        curr_iof = path.get_iof()
        # Preconditions
        assert curr_iof.info == OFT.CORE

        self.verify_hof(path)
        if path.is_last_path_hof():
            self.deliver(spkt, PT.DATA)
        else:
            path.next_segment()
            fwd_if = path.get_fwd_if()
            # Check interface availability.
            self._revoke_if_down(fwd_if, spkt)
            self.send(spkt, self.ifid2addr[fwd_if])

    def ingress_normal_forward(self, spkt):
        """
        Handles normal forwarding of packets at the ingress router.
        """
        path = spkt.path
        self.verify_hof(path)
        fwd_if = path.get_fwd_if()
        # Check interface availability.
        self._revoke_if_down(fwd_if, spkt)
        if not fwd_if and path.is_last_path_hof():
            self.deliver(spkt, PT.DATA)
        else:
            self.send(spkt, self.ifid2addr[fwd_if])

    def handle_egress_xovr(self, spkt):
        """
        Main entry for crossover points at the egress router.
        """
        path = spkt.path
        curr_hof = path.get_hof()
        curr_iof = path.get_iof()
        # Preconditions
        assert curr_hof.is_xovr()

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
        path = spkt.path
        curr_hof = path.get_hof()
        curr_iof = path.get_iof()
        # Preconditions
        assert curr_hof.is_xovr()
        assert curr_iof.info == OFT.SHORTCUT
        if path.is_on_up_path():
            raise SCIONPacketHeaderCorruptedError

        self.egress_normal_forward(spkt)

    def egress_peer_xovr(self, spkt):
        """
        Handles the crossover point for peer paths at the egress router.
        """
        path = spkt.path
        curr_hof = path.get_hof()
        curr_iof = path.get_iof()
        # Preconditions
        assert curr_hof.is_xovr()
        assert curr_iof.info in [OFT.INTRA_ISD_PEER, OFT.INTER_ISD_PEER]

        self.verify_hof(path, ingress=False)
        if path.is_on_up_path():
            path.next_segment()
        else:
            path.inc_hof_idx()
        self.send(spkt, self.interface.to_addr, self.interface.to_udp_port)

    def egress_core_xovr(self, spkt):
        """
        Handles the crossover point for core paths at the egress router.
        """
        path = spkt.path
        curr_hof = path.get_hof()
        curr_iof = path.get_iof()
        # Preconditions
        assert curr_hof.is_xovr()
        assert curr_iof.info == OFT.CORE

        self.verify_hof(path, ingress=False)
        path.inc_hof_idx()
        self.send(spkt, self.interface.to_addr, self.interface.to_udp_port)

    def egress_normal_forward(self, spkt):
        """
        Handles normal forwarding of packets at the egress router.
        """
        path = spkt.path
        self.verify_hof(path, ingress=False)
        path.inc_hof_idx()
        self.send(spkt, self.interface.to_addr, self.interface.to_udp_port)

    def forward_packet(self, spkt, from_local_ad):
        """
        Main entry point for data packet forwarding.

        :param spkt: The SCION Packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param from_local_ad: Whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        curr_hof = spkt.path.get_hof()
        try:
            # Ingress entry point.
            if not from_local_ad:
                if curr_hof.info == OFT.XOVR_POINT:
                    self.handle_ingress_xovr(spkt)
                else:
                    self.ingress_normal_forward(spkt)
            # Egress entry point.
            else:
                if curr_hof.info == OFT.XOVR_POINT:
                    self.handle_egress_xovr(spkt)
                else:
                    self.egress_normal_forward(spkt)
        except SCIONOFVerificationError as e:
            logging.error("Dropping packet due to incorrect MAC.\n"
                          "Header:\n%s\nInvalid OF: %s\nPrev OF: %s",
                          spkt, e.args[0], e.args[1])
        except SCIONOFExpiredError as e:
            logging.error("Dropping packet due to expired OF.\n"
                          "Header:\n%s\nExpired OF: %s",
                          spkt, e)
        except SCIONPacketHeaderCorruptedError:
            logging.error("Dropping packet due to invalid header state.\n"
                          "Header:\n%s", spkt)
        except SCIONInterfaceDownException:
            pass

    def _needs_local_processing(self, pkt):
        return (
            (
                # Destination is this router.
                pkt.addrs.dst_isd == self.addr.isd_id and
                pkt.addrs.dst_ad == self.addr.ad_id and
                pkt.addrs.dst_addr in (self.addr.host_addr, self.interface.addr)
            ) or (
                # Destination is an SVC address.
                pkt.addrs.dst_addr.TYPE == AddrType.SVC
            ) or (
                # FIXME(kormat): temporary hack until revocations are handled
                # in extension header
                pkt.addrs.src_addr.TYPE == AddrType.SVC
            )
        )

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
        try:
            pkt = SCIONL4Packet(packet)
        except SCIONBaseError:
            log_exception("Error parsing packet: %s" % packet,
                          level=logging.ERROR)
            return
        if self.handle_extensions(pkt, True):
            # An extention handler has taken care of the packet, so we stop
            # processing it.
            return
        if self._needs_local_processing(pkt):
            try:
                pkt.parse_payload()
            except SCIONBaseError:
                log_exception("Error parsing payload:\n%s" % pkt)
                return
            handler = self._get_handler(pkt)
        else:
            # It's a normal packet, just forward it.
            handler = self.forward_packet
        logging.debug("handle_request: pkt addrs: %s handler: %s",
                      pkt.addrs, handler)
        if not handler:
            return
        try:
            handler(pkt, from_local_ad)
        except SCIONBaseError:
            log_exception("Error handling packet: %s" % pkt)


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
