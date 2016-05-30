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
import copy
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
    MAX_HOPBYHOP_EXT,
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
from lib.packet.ifid import IFIDPayload
from lib.packet.path_mgmt.ifstate import IFStateInfo, IFStateRequest
from lib.packet.scion import SVCType
from lib.packet.scmp.errors import (
    SCMPBadExtOrder,
    SCMPBadHopByHop,
    SCMPBadHost,
    SCMPBadIF,
    SCMPBadMAC,
    SCMPDeliveryFwdOnly,
    SCMPDeliveryNonLocal,
    SCMPError,
    SCMPExpiredHOF,
    SCMPNonRoutingHOF,
    SCMPPathRequired,
    SCMPTooManyHopByHop,
    SCMPUnknownHost,
)
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.sibra.state.state import SibraState
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import (
    AddrType,
    ExtHopByHopType,
    ExtensionClass,
    IFIDType,
    PCBType,
    PathMgmtType as PMT,
    PayloadClass,
    RouterFlag,
    SIBRAPayloadType,
)
from lib.util import SCIONTime, hex_str, sleep_interval


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
            ExtHopByHopType.SCMP: self.handle_scmp,
        }
        self.post_ext_handlers = {
            SibraExtBase.EXT_TYPE: False, TracerouteExt.EXT_TYPE: False,
            ExtHopByHopType.SCMP: False,
        }
        self.sibra_state = SibraState(
            self.interface.bandwidth,
            "%s#%s -> %s" % (self.addr.isd_as, self.interface.if_id,
                             self.interface.isd_as))
        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.PCB: {PCBType.SEGMENT: self.process_pcb},
            PayloadClass.IFID: {IFIDType.PAYLOAD: self.process_ifid_request},
            PayloadClass.CERT: defaultdict(
                lambda: self.relay_cert_server_packet),
            PayloadClass.PATH: defaultdict(
                lambda: self.process_path_mgmt_packet),
            PayloadClass.SIBRA: {SIBRAPayloadType.EMPTY:
                                 self.fwd_sibra_service_pkt},
        }
        self.SCMP_PLD_CLASS_MAP = {
            SCMPClass.PATH: {SCMPPathClass.REVOKED_IF: self.process_revocation},
        }
        self._remote_sock = UDPSocket(
            bind=(str(self.interface.addr), self.interface.udp_port),
            addr_type=AddrType.IPV4,
        )
        self._socks.add(self._remote_sock, self.handle_recv)
        logging.info("IP %s:%d", self.interface.addr, self.interface.udp_port)

    def _setup_socket(self, init=True):
        """
        Setup incoming socket
        """
        # FIXME(kormat): reuse=True should to away once the dispatcher and the
        # router no longer try binding to the same socket.
        self._local_sock = UDPSocket(
            bind=(str(self.addr.host), SCION_UDP_EH_DATA_PORT, self.id),
            addr_type=self.addr.host.TYPE, reuse=True,
        )
        self._port = self._local_sock.port
        self._socks.add(self._local_sock, self.handle_recv)

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
        threading.Thread(
            target=thread_safety_net, args=(self.sibra_worker,),
            name="ER.sibra_worker", daemon=True).start()
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
            self._local_sock.send(spkt.pack(), (str(addr), port))

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
        # only MAX_HOPBYHOP_EXT number of them. If an SCMP ext header is
        # present, it must be the first hopbyhop extension (and isn't included
        # in the MAX_HOPBYHOP_EXT check).
        count = 0
        for i, ext_hdr in enumerate(spkt.ext_hdrs):
            if ext_hdr.EXT_CLASS != ExtensionClass.HOP_BY_HOP:
                break
            if ext_hdr.EXT_TYPE == ExtHopByHopType.SCMP:
                if i != 0:
                    logging.error("SCMP ext header not first.")
                    raise SCMPBadExtOrder(i)
            else:
                count += 1
            if count > MAX_HOPBYHOP_EXT:
                logging.error("Too many hop-by-hop extensions.")
                raise SCMPTooManyHopByHop(i)
            handler = handlers.get(ext_hdr.EXT_TYPE)
            if handler is None:
                logging.debug("No %s-handler for extension type %s",
                              prefix, ext_hdr.EXT_TYPE)
                raise SCMPBadHopByHop
            if handler:
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

    def handle_scmp(self, hdr, spkt, _):
        if hdr.hopbyhop:
            return [(RouterFlag.PROCESS_LOCAL,)]
        return []

    def sync_interface(self):
        """
        Synchronize and initialize the router's interface with that of a
        neighboring router.
        """
        ifid_pld = IFIDPayload.from_values(self.interface.if_id)
        pkt = self._build_packet(SVCType.BS, dst_ia=self.interface.isd_as)
        while True:
            pkt.set_payload(ifid_pld.copy())
            self.send(pkt, self.interface.to_addr, self.interface.to_udp_port)
            time.sleep(IFID_PKT_TOUT)

    def request_ifstates(self):
        """
        Periodically request interface states from the BS.
        """
        pld = IFStateRequest.from_values()
        req = self._build_packet()
        while True:
            start_time = SCIONTime.get_time()
            logging.info("Sending IFStateRequest for all interfaces.")
            for bs in self.topology.beacon_servers:
                req.addrs.dst.host = bs.addr
                req.set_payload(pld.copy())
                self.send(req)
            sleep_interval(start_time, self.IFSTATE_REQ_INTERVAL,
                           "request_ifstates")

    def sibra_worker(self):
        while True:
            start_time = SCIONTime.get_time()
            self.sibra_state.update_tick()
            sleep_interval(start_time, 1.0, "sibra_worker")

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
        if pkt.addrs.dst.host != SVCType.BS:
            raise SCMPBadHost("Invalid SVC address: %s", pkt.addrs.dst.host)
        ifid_pld = pkt.get_payload().copy()
        # Forward 'alive' packet to all BSes (to inform that neighbor is alive).
        # BS must determine interface.
        ifid_pld.p.relayIF = self.interface.if_id
        try:
            bs_addrs = self.dns_query_topo(BEACON_SERVICE)
        except SCIONServiceLookupError as e:
            logging.error("Unable to deliver ifid packet: %s", e)
            raise SCMPUnknownHost
        for bs_addr in bs_addrs:
            pkt.set_payload(ifid_pld.copy())
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
                raise SCMPUnknownHost
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
                raise SCMPUnknownHost
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
            raise SCMPUnknownHost
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
            for p in payload.p.infos:
                self.if_states[p.ifID].update(IFStateInfo(p))
            return
        self.handle_data(mgmt_pkt, from_local_as)

    def process_revocation(self, spkt, from_local_as):
        pld = spkt.get_payload()
        logging.info("Processing revocation: %s", pld.info)
        # First, forward the packet as appropriate.
        self.handle_data(spkt, from_local_as)
        if from_local_as:
            return
        # Forward to local path server if we haven't recently.
        rev_token = pld.info.rev_token
        if (self.topology.path_servers and
                rev_token not in self.revocations):
            self.revocations[rev_token] = True
            try:
                ps = self.get_srv_addr(PATH_SERVICE, spkt)
            except SCIONServiceLookupError:
                logging.error("No local PS to forward revocation to.")
                raise SCMPUnknownHost
            ps_pkt = copy.deepcopy(spkt)
            ps_pkt.addrs.dst.isd_as = self.addr.isd_as
            ps_pkt.addrs.dst.host = ps
            # FIXME(kormat): disabling for now, as this doesn't currently work.
            # The dispatcher has no way to route the revocation scmp message to
            # the designated path server.
            logging.debug("DISABLED: Forwarding revocation to local PS: %s", ps)
            # self.send(spkt, ps)
        self.handle_data(spkt, from_local_as)

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

        rev_pkt = spkt.reversed_copy()
        rev_pkt.convert_to_scmp_error(
            self.addr, SCMPClass.PATH, SCMPPathClass.REVOKED_IF, spkt, if_id,
            ingress, if_state.rev_token, hopbyhop=True)
        if path_incd:
            rev_pkt.path.inc_hof_idx()
        rev_pkt.update()
        logging.debug("Revocation Packet:\n%s", rev_pkt)
        # FIXME(kormat): In some circumstances, this doesn't actually work, as
        # handle_data will try to send the packet to this interface first, and
        # then drop the packet as the interface is down.
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
            raise SCMPDeliveryNonLocal
        if len(spkt.path):
            hof = spkt.path.get_hof()
            if not force and hof.forward_only:
                raise SCMPDeliveryFwdOnly
            if hof.verify_only:
                raise SCMPNonRoutingHOF
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
                raise SCMPUnknownHost
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
            raise SCMPBadMAC from None
        except SCIONOFExpiredError as e:
            logging.error("Dropping packet due to expired OF.\n"
                          "Header:\n%s\nExpired OF: %s",
                          spkt, e)
            raise SCMPExpiredHOF from None
        except SCIONPacketHeaderCorruptedError:
            logging.error("Dropping packet due to invalid header state.\n"
                          "Header:\n%s", spkt)
        except SCIONInterfaceDownException:
            logging.debug("Dropping packet due to interface being down")
            pass

    def _process_data(self, spkt, ingress, drop_on_error):
        path = spkt.path
        if len(spkt) > self.topology.mtu:
            # FIXME(kormat): ignore this check for now, as PCB packets are often
            # over MTU, it's just that udp-overlay handles fragmentation for us.
            # Once we have TCP/SCION, this check should be re-instated.
            # This also needs to look at the specific MTU for the relevant link
            # if on egress.
            #  raise SCMPOversizePkt("Packet larger than mtu", mtu)
            pass
        self.verify_hof(path, ingress=ingress)
        hof = spkt.path.get_hof()
        if hof.verify_only:
            raise SCMPNonRoutingHOF
        if spkt.addrs.dst.isd_as == self.addr.isd_as:
            self.deliver(spkt)
            return
        if ingress:
            fwd_if, path_incd = self._calc_fwding_ingress(spkt)
        else:
            fwd_if = path.get_fwd_if()
            path_incd = False
        try:
            if_addr = self.ifid2addr[fwd_if]
        except KeyError:
            # So that the error message will show the current state of the
            # packet.
            spkt.update()
            logging.error("Cannot forward packet, fwd_if is invalid (%s):\n%s",
                          fwd_if, spkt)
            raise SCMPBadIF(fwd_if) from None
        if not self.if_states[fwd_if].is_active:
            if drop_on_error:
                logging.debug("IF is down, but drop_on_error is set, dropping")
                return
            self.send_revocation(spkt, fwd_if, ingress, path_incd)
            return
        if ingress:
            logging.debug("Sending to IF %s (%s)", fwd_if, if_addr)
            self.send(spkt, if_addr)
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
        if len(pkt.path) == 0:
            if pkt.addrs.dst.host.TYPE == AddrType.SVC:
                # Always process packets with SVC destinations and no path
                return True
            elif pkt.addrs.dst == self.addr:
                # Destination is the internal address of this router.
                return True
            raise SCMPPathRequired
        if (pkt.addrs.dst.isd_as == self.addr.isd_as and
                pkt.addrs.dst.host.TYPE == AddrType.SVC):
            # Destination is a local SVC address.
            return True
        return False

    def _process_flags(self, flags, pkt, from_local_as):
        """
        Go through the flags set by hop-by-hop extensions on this packet.
        :returns:
        """
        process = False
        # First check if any error or no_process flags are set
        for (flag, *args) in flags:
            if flag == RouterFlag.ERROR:
                logging.error("%s", args[0])
                return True, False
            elif flag == RouterFlag.NO_PROCESS:
                return True, False
        # Now check for other flags
        for (flag, *args) in flags:
            if flag == RouterFlag.FORWARD:
                if from_local_as:
                    self._process_fwd_flag(pkt)
                else:
                    self._process_fwd_flag(pkt, args[0])
                return True, False
            elif flag in (RouterFlag.DELIVER, RouterFlag.FORCE_DELIVER):
                self._process_deliver_flag(pkt, flag)
                return True, False
            elif flag == RouterFlag.PROCESS_LOCAL:
                process = True
        return False, process

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

    def handle_request(self, packet, _, from_local_socket=True, sock=None):
        """
        Main routine to handle incoming SCION packets.

        :param bytes packet: The incoming packet to handle.
        :param tuple sender: Tuple of sender IP, port.
        :param bool from_local_socket:
            True, if the packet was received on the local socket.
        """
        from_local_as = from_local_socket
        pkt = self._parse_packet(packet)
        if not pkt:
            return
        if pkt.ext_hdrs:
            logging.debug("Got packet (from_local_as? %s):\n%s",
                          from_local_as, pkt)
        try:
            flags = self.handle_extensions(pkt, True, from_local_as)
        except SCMPError as e:
            self._scmp_validate_error(pkt, e)
            return
        stop, needs_local = self._process_flags(flags, pkt, from_local_as)
        if stop:
            logging.debug("Stopped processing")
            return
        try:
            needs_local |= self._needs_local_processing(pkt)
        except SCMPError as e:
            self._scmp_validate_error(pkt, e)
            return
        if needs_local:
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
        except SCMPError as e:
            self._scmp_validate_error(pkt, e)
        except SCIONBaseError:
            log_exception("Error handling packet: %s" % pkt)
