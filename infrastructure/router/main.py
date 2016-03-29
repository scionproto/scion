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
import logging
import threading
import time
import zlib
from collections import defaultdict

# External packages
from Crypto.Protocol.KDF import PBKDF2

# SCION
from external.expiring_dict import ExpiringDict
from infrastructure.router.if_state import InterfaceState
from infrastructure.router.errors import (
    SCIONInterfaceDownException,
    SCIONOFExpiredError,
    SCIONOFVerificationError,
    SCIONPacketHeaderCorruptedError,
)
from infrastructure.scion_elem import SCIONElement
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    EXP_TIME_UNIT,
    IFID_PKT_TOUT,
    PATH_SERVICE,
    ROUTER_SERVICE,
    SCION_UDP_EH_DATA_PORT,
    SIBRA_SERVICE,
)
from lib.errors import (
    SCIONBaseError,
    SCIONServiceLookupError,
)
from lib.log import log_exception
from lib.sibra.ext.ext import SibraExtBase
from lib.packet.ext.traceroute import TracerouteExt
from lib.packet.path_mgmt import RevocationInfo, IFStateRequest
from lib.packet.scion import (
    IFIDPayload,
    SCIONL4Packet,
    SVCType,
)
from lib.sibra.state.state import SibraState
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import (
    AddrType,
    ExtensionClass,
    IFIDType,
    PCBType,
    PathMgmtType as PMT,
    PayloadClass,
    RouterFlag,
    SIBRAPayloadType,
)
from lib.util import SCIONTime, hex_str, sleep_interval


MAX_EXT = 4  # Maximum number of hop-by-hop extensions processed by router.


class Router(SCIONElement):
    """
    The SCION Router.

    :ivar addr: the router address.
    :type addr: :class:`SCIONAddr`
    :ivar topology: the AS topology as seen by the router.
    :type topology: :class:`Topology`
    :ivar config: the configuration of the router.
    :type config: :class:`Config`
    :ivar dict ifid2addr:
        a map from interface identifiers to the corresponding border router
        addresses in the server's AS.
    :ivar interface: the router's inter-AS interface, if any.
    :type interface: :class:`lib.topology.InterfaceElement`
    """
    SERVICE_TYPE = ROUTER_SERVICE
    FWD_REVOCATION_TIMEOUT = 5
    IFSTATE_REQ_INTERVAL = 30

    def __init__(self, server_id, conf_dir, ):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir, )
        self.interface = None
        for edge_router in self.topology.get_all_edge_routers():
            if edge_router.addr == self.addr.host:
                self.interface = edge_router.interface
                break
        assert self.interface is not None
        logging.info("Interface: %s", self.interface.__dict__)
        self.of_gen_key = PBKDF2(self.config.master_as_key, b"Derive OF Key")
        self.sibra_key = PBKDF2(self.config.master_as_key, b"Derive SIBRA Key")
        self.if_states = defaultdict(InterfaceState)
        self.revocations = ExpiringDict(1000, self.FWD_REVOCATION_TIMEOUT)
        self.pre_ext_handlers = {
            SibraExtBase.EXT_TYPE: self.handle_sibra,
            TracerouteExt.EXT_TYPE: self.handle_traceroute,
        }
        self.post_ext_handlers = {}
        self.sibra_state = SibraState(self.interface.bandwidth,
                                      self.addr.isd_as)

        self.PLD_CLASS_MAP = {
            PayloadClass.PCB: {PCBType.SEGMENT: self.process_pcb},
            PayloadClass.IFID: {IFIDType.PAYLOAD: self.process_ifid_request},
            PayloadClass.CERT: defaultdict(
                lambda: self.relay_cert_server_packet),
            PayloadClass.PATH: defaultdict(
                lambda: self.process_path_mgmt_packet),
            PayloadClass.SIBRA: {SIBRAPayloadType.EMPTY:
                                 self.fwd_sibra_service_pkt},
        }

        self._remote_sock = UDPSocket(
            bind=(str(self.interface.addr), self.interface.udp_port),
            addr_type=AddrType.IPV4,
        )
        self._socks.add(self._remote_sock)
        logging.info("IP %s:%d", self.interface.addr, self.interface.udp_port)

    def _setup_socket(self):
        """
        Setup incoming socket
        """
        self._local_sock = UDPSocket(
            bind=(str(self.addr.host), SCION_UDP_EH_DATA_PORT, self.id),
            addr_type=self.addr.host.TYPE,
        )
        self._port = self._local_sock.port
        self._socks.add(self._local_sock)

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

    def send(self, spkt, addr=None, port=SCION_UDP_EH_DATA_PORT):
        """
        Send a spkt to addr (class of that object must implement
        __str__ which returns IPv4 addr) using port and local or remote
        socket. If addr isn't set, use the destination address in the packet.

        :param spkt: The packet to send.
        :type spkt: :class:`lib.spkt.SCIONspkt`
        :param addr: The address of the next hop.
        :type addr: :class:`IPv4Adress`
        :param int port: The port number of the next hop.
        """
        if addr is None:
            addr = spkt.addrs.dst.host
        from_local_as = addr == self.interface.to_addr
        self.handle_extensions(spkt, False, from_local_as)
        if from_local_as:
            self._remote_sock.send(spkt.pack(), (str(addr), port))
        else:
            super().send(spkt, addr, port)

    def handle_extensions(self, spkt, pre_routing_phase, from_local_as):
        """
        Handle SCION Packet extensions. Handlers can be defined for pre- and
        post-routing.
        """
        if pre_routing_phase:
            prefix = "pre"
            handlers = self.pre_ext_handlers
        else:
            prefix = "post"
            handlers = self.post_ext_handlers
        flags = []
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
                logging.debug("No %s-handler for extension type %s",
                              prefix, ext_hdr.EXT_TYPE)
                continue
            flags.extend(handler(ext_hdr, spkt, from_local_as))
        return flags

    def handle_traceroute(self, hdr, spkt, _):
        # Truncate milliseconds to 2B
        hdr.append_hop(self.addr.isd_as, self.interface.if_id)
        return []

    def handle_sibra(self, hdr, spkt, from_local_as):
        ret = hdr.process(self.sibra_state, spkt, from_local_as,
                          self.sibra_key)
        logging.debug("Sibra state:\n%s", self.sibra_state)
        return ret

    def sync_interface(self):
        """
        Synchronize and initialize the router's interface with that of a
        neighboring router.
        """
        ifid_pld = IFIDPayload.from_values(self.interface.if_id)
        pkt = self._build_packet(SVCType.BS, dst_ia=self.interface.isd_as,
                                 payload=ifid_pld)
        while True:
            self.send(pkt, self.interface.to_addr, self.interface.to_udp_port)
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
                req_pkt.addrs.dst.host = bs.addr
                self.send(req_pkt)
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
        For a given service return a server address. Guarantee that all packets
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
        :param bool from_bs: True, if the beacon was received from local BS.
        """
        pcb = pkt.get_payload()
        if from_bs:
            if self.interface.if_id != pcb.get_last_pcbm().hof.egress_if:
                logging.error("Wrong interface set by BS.")
                return
            self.send(pkt, self.interface.to_addr, self.interface.to_udp_port)
        else:
            pcb.if_id = self.interface.if_id
            try:
                bs_addr = self.get_srv_addr(BEACON_SERVICE, pkt)
            except SCIONServiceLookupError as e:
                logging.error("Unable to deliver PCB: %s", e)
                return
            self.send(pkt, bs_addr)

    def relay_cert_server_packet(self, spkt, from_local_as):
        """
        Relay packets for certificate servers.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param bool from_local_as:
            whether or not the packet is from the local AS.
        """
        if from_local_as:
            addr = self.interface.to_addr
            port = self.interface.to_udp_port
        else:
            try:
                addr = self.get_srv_addr(CERTIFICATE_SERVICE, spkt)
            except SCIONServiceLookupError as e:
                logging.error("Unable to deliver cert packet: %s", e)
                return
            port = SCION_UDP_EH_DATA_PORT
        self.send(spkt, addr, port)

    def fwd_sibra_service_pkt(self, spkt, _):
        """
        Forward SIBRA service packets to a SIBRA server.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        """
        try:
            addr = self.get_srv_addr(SIBRA_SERVICE, spkt)
        except SCIONServiceLookupError as e:
            logging.error("Unable to deliver sibra service packet: %s", e)
            return
        self.send(spkt, addr)

    def process_path_mgmt_packet(self, mgmt_pkt, from_local_as):
        """
        Process path management packets.

        :param mgmt_pkt: The path mgmt packet.
        :type mgmt_pkt: :class:`lib.packet.path_mgmt.PathMgmtPacket`
        :param bool from_local_as:
            whether or not the packet is from the local AS.
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
            if not from_local_as:
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
                    self.send(mgmt_pkt, ps)
        self.handle_data(mgmt_pkt, from_local_as)

    def send_revocation(self, spkt, if_id, ingress, path_incd):
        """
        Sends an interface revocation for 'if_id' along the path in 'spkt'.
        """
        logging.info("Interface %d is down. Issuing revocation.", if_id)
        # Check that the interface is really down.
        if_state = self.if_states[if_id]
        if self.if_states[if_id].is_active:
            logging.error("Interface %d appears to be up. Not sending " +
                          "revocation." % if_id)
            return

        assert if_state.rev_token, "Revocation token missing."

        rev_info = RevocationInfo.from_values(if_state.rev_token)
        rev_pkt = spkt.reversed_copy()
        if path_incd:
            rev_pkt.path.inc_hof_idx()
        rev_pkt.set_payload(rev_info)
        rev_pkt.addrs.src.host = SVCType.PS
        rev_pkt.update()
        logging.debug("Revocation Packet:\n%s", rev_pkt)
        self.handle_data(rev_pkt, ingress, drop_on_error=True)

    def deliver(self, spkt, force=True):
        """
        Forwards the packet to the end destination within the current AS.

        :param spkt: The SCION Packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param bool force:
            If set, allow packets to be delivered locally that would otherwise
            be disallowed.
        """
        if not force and spkt.addrs.dst.isd_as != self.addr.isd_as:
            logging.error("Tried to deliver a non-local packet:\n%s", spkt)
            return
        if len(spkt.path):
            hof = spkt.path.get_hof()
            if not force:
                assert not hof.forward_only
            assert not hof.verify_only
        # Forward packet to destination.
        addr = spkt.addrs.dst.host
        if addr == SVCType.PS:
            # FIXME(PSz): that should be changed when replies are send as
            # standard data packets.
            # Send request to any path server.
            try:
                addr = self.get_srv_addr(PATH_SERVICE, spkt)
            except SCIONServiceLookupError as e:
                logging.error("Unable to deliver path mgmt packet: %s", e)
                return
        elif addr == SVCType.SB:
            self.fwd_sibra_service_pkt(spkt, None)
            return
        self.send(spkt, addr)

    def verify_hof(self, path, ingress=True):
        """Verify freshness and authentication of an opaque field."""
        ts = path.get_iof().timestamp
        hof = path.get_hof()
        prev_hof = path.get_hof_ver(ingress=ingress)
        if int(SCIONTime.get_time()) <= ts + hof.exp_time * EXP_TIME_UNIT:
            if not hof.verify_mac(self.of_gen_key, ts, prev_hof):
                raise SCIONOFVerificationError(hof, prev_hof)
        else:
            raise SCIONOFExpiredError(hof)

    def _egress_forward(self, spkt):
        logging.debug("Forwarding to remote interface: %s:%s",
                      self.interface.to_addr, self.interface.to_udp_port)
        self.send(spkt, self.interface.to_addr, self.interface.to_udp_port)

    def handle_data(self, spkt, from_local_as, drop_on_error=False):
        """
        Main entry point for data packet handling.

        :param spkt: The SCION Packet to process.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param from_local_as:
            Whether or not the packet is from the local AS.
        """
        ingress = not from_local_as
        try:
            self._process_data(spkt, ingress, drop_on_error)
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

    def _process_data(self, spkt, ingress, drop_on_error):
        path = spkt.path
        self.verify_hof(path, ingress=ingress)
        if spkt.addrs.dst.isd_as == self.addr.isd_as:
            self.deliver(spkt)
            return
        if ingress:
            fwd_if, path_incd = self._calc_fwding_ingress(spkt)
        else:
            fwd_if = path.get_fwd_if()
            path_incd = False
        if fwd_if == 0:
            # So that the error message will show the current state of the
            # packet.
            spkt.update()
            logging.error("Cannot forward packet, fwd_if is 0:\n%s", spkt)
            return
        if not self.if_states[fwd_if].is_active:
            if drop_on_error:
                logging.debug("IF is down, but drop_on_error is set, dropping")
                return
            self.send_revocation(spkt, fwd_if, ingress, path_incd)
            raise SCIONInterfaceDownException(fwd_if)
        if ingress:
            logging.debug("Sending to IF %s (%s)", fwd_if,
                          self.ifid2addr[fwd_if])
            self.send(spkt, self.ifid2addr[fwd_if])
        else:
            path.inc_hof_idx()
            self._egress_forward(spkt)

    def _calc_fwding_ingress(self, spkt):
        path = spkt.path
        hof = path.get_hof()
        incd = False
        if hof.xover:
            path.inc_hof_idx()
            incd = True
        return path.get_fwd_if(), incd

    def _needs_local_processing(self, pkt):
        if len(pkt.path) == 0 and pkt.addrs.dst.host.TYPE == AddrType.SVC:
            # Always process packets with SVC destinations and no path
            return True
        if pkt.addrs.src.host == SVCType.PS:
            # FIXME(kormat): temporary hack until revocations are handled
            # by SCMP
            return True
        if pkt.addrs.dst.isd_as == self.addr.isd_as:
            # Destination is the local AS.
            if pkt.addrs.dst.host in (self.addr.host, self.interface.addr):
                # Destination is this router.
                return True
            if pkt.addrs.dst.host.TYPE == AddrType.SVC:
                # Destination is a local SVC address.
                return True
        return False

    def _process_flags(self, flags, pkt, from_local_as):
        """
        Go through the flags set by hop-by-hop extensions on this packet.
        """
        # First check if any error or no_process flags are set
        for (flag, *args) in flags:
            if flag == RouterFlag.ERROR:
                logging.error("%s", args[0])
                return False
            elif flag == RouterFlag.NO_PROCESS:
                return False
        # Now check for other flags
        for (flag, *args) in flags:
            if flag == RouterFlag.FORWARD:
                if from_local_as:
                    self._process_fwd_flag(pkt)
                else:
                    self._process_fwd_flag(pkt, args[0])
                return False
            elif flag in (RouterFlag.DELIVER, RouterFlag.FORCE_DELIVER):
                self._process_deliver_flag(pkt, flag)
                return False
        return True

    def _process_fwd_flag(self, pkt, ifid=None):
        if ifid is None:
            logging.debug("Packet forwarded over link by extension")
            self._egress_forward(pkt)
            return
        if ifid == 0:
            logging.error("Extension asked to forward this to interface 0:\n%s",
                          pkt)
            return
        next_hop = self.ifid2addr[ifid]
        logging.debug("Packet forwarded by extension via %s", next_hop)
        self.send(pkt, next_hop)

    def _process_deliver_flag(self, pkt, flag):
        if (flag == RouterFlag.DELIVER and
                pkt.addrs.dst.isd_as != self.addr.isd_as):
            logging.error("Extension tried to deliver this locally, but this "
                          "is not the destination ISD-AS:\n%s", pkt)
            return
        logging.debug("Packet delivered by extension")
        self.deliver(pkt)

    def handle_request(self, packet, _, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.

        :param bytes packet: The incoming packet to handle.
        :param tuple sender: Tuple of sender IP, port.
        :param bool from_local_socket:
            True, if the packet was received on the local socket.
        """
        from_local_as = from_local_socket
        try:
            pkt = SCIONL4Packet(packet)
        except SCIONBaseError:
            log_exception("Error parsing packet: %s" % hex_str(packet),
                          level=logging.ERROR)
            return
        if pkt.ext_hdrs:
            logging.debug("Got packet (from_local_as? %s):\n%s",
                          from_local_as, pkt)
        flags = self.handle_extensions(pkt, True, from_local_as)
        if not self._process_flags(flags, pkt, from_local_as):
            logging.debug("Stopped processing")
            return
        if self._needs_local_processing(pkt):
            try:
                pkt.parse_payload()
            except SCIONBaseError:
                log_exception("Error parsing payload:\n%s" % hex_str(packet))
                return
            handler = self._get_handler(pkt)
        else:
            # It's a normal packet, just forward it.
            handler = self.handle_data
        logging.debug("handle_request (from_local_as? %s):"
                      "\n  %s\n  %s\n  handler: %s",
                      from_local_as, pkt.cmn_hdr, pkt.addrs, handler)
        if not handler:
            return
        try:
            handler(pkt, from_local_as)
        except SCIONBaseError:
            log_exception("Error handling packet: %s" % pkt)
