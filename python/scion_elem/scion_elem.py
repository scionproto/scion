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
:mod:`scion_elem` --- Base class for SCION servers
==================================================
"""
# Stdlib
import copy
import logging
import os
import queue
import threading
import time
from collections import defaultdict

# External packages
from external.expiring_dict import ExpiringDict
from prometheus_client import Counter, Gauge, start_http_server

# SCION
import lib.app.sciond as lib_sciond
from lib.config import Config
from lib.crypto.certificate_chain import verify_chain_trc
from lib.crypto.hash_tree import ConnectedHashTree
from lib.errors import SCIONParseError, SCIONVerificationError
from lib.flagtypes import TCPFlags
from lib.defines import (
    AS_CONF_FILE,
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    GEN_CACHE_PATH,
    PATH_SERVICE,
    SCION_UDP_EH_DATA_PORT,
    SCIOND_API_SOCKDIR,
    SERVICE_TYPES,
    SIBRA_SERVICE,
    STARTUP_QUIET_PERIOD,
    TCP_ACCEPT_POLLING_TOUT,
    TOPO_FILE,
)
from lib.errors import (
    SCIONBaseError,
    SCIONChecksumFailed,
    SCIONTCPError,
    SCIONTCPTimeout,
    SCIONServiceLookupError,
)
from lib.log import log_exception
from lib.msg_meta import (
    SCMPMetadata,
    SockOnlyMetadata,
    TCPMetadata,
    UDPMetadata,
)
from lib.packet.cert_mgmt import (
    CertMgmt,
    CertChainReply,
    CertChainRequest,
    TRCReply,
    TRCRequest,
)
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.ext.one_hop_path import OneHopPathExt
from lib.packet.host_addr import HostAddrNone
from lib.packet.packet_base import PayloadRaw
from lib.packet.path import SCIONPath
from lib.packet.scion import (
    SCIONBasePacket,
    SCIONL4Packet,
    build_base_hdrs,
)
from lib.packet.svc import SVC_TO_SERVICE, SERVICE_TO_SVC_A
from lib.packet.scion_addr import SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.packet.scmp.errors import (
    SCMPBadDstType,
    SCMPBadExtOrder,
    SCMPBadHOFOffset,
    SCMPBadHopByHop,
    SCMPBadIOFOffset,
    SCMPBadPktLen,
    SCMPBadSrcType,
    SCMPBadVersion,
    SCMPError,
    SCMPOversizePkt,
    SCMPTooManyHopByHop,
    SCMPUnspecified,
)
from lib.packet.scmp.types import SCMPClass
from lib.packet.scmp.util import scmp_type_name
from lib.socket import ReliableSocket, SocketMgr, TCPSocketWrapper
from lib.tcp.socket import SCIONTCPSocket, SockOpt
from lib.thread import thread_safety_net, kill_self
from lib.trust_store import TrustStore
from lib.types import AddrType, L4Proto, PayloadClass
from lib.topology import Topology
from lib.util import hex_str, sleep_interval


# Exported metrics.
PKT_BUF_TOTAL = Gauge("se_pkt_buf_total", "Total packets in input buffer",
                      ["server_id", "isd_as"])
PKT_BUF_BYTES = Gauge("se_pkt_buf_bytes", "Memory usage of input buffer",
                      ["server_id", "isd_as"])
PKTS_DROPPED_TOTAL = Counter("se_packets_dropped_total", "Total packets dropped",
                             ["server_id", "isd_as"])
UNV_SEGS_TOTAL = Gauge("se_unverified_segs_total", "# of unverified segments",
                       ["server_id", "isd_as"])
PENDING_TRC_REQS_TOTAL = Gauge("se_pending_trc_reqs", "# of pending TRC requests",
                               ["server_id", "isd_as"])
PENDING_CERT_REQS_TOTAL = Gauge("se_pending_cert_reqs", "# of pending CERT requests",
                                ["server_id", "isd_as"])
CONNECTED_TO_DISPATCHER = Gauge(
    "se_connected_to_dispatcher",
    "Is the element successfully registered with the dispatcher.",
    ["server_id", "isd_as"])

MAX_QUEUE = 50
# Timeout for API path requests
API_TOUT = 1


class SCIONElement(object):
    """
    Base class for the different kind of servers the SCION infrastructure
    provides.

    :ivar `Topology` topology: the topology of the AS as seen by the server.
    :ivar `Config` config:
        the configuration of the AS in which the server is located.
    :ivar dict ifid2br: map of interface ID to RouterElement.
    :ivar `SCIONAddr` addr: the server's address.
    """
    SERVICE_TYPE = None
    STARTUP_QUIET_PERIOD = STARTUP_QUIET_PERIOD
    USE_TCP = False
    # Timeout for TRC or Certificate requests.
    TRC_CC_REQ_TIMEOUT = 3

    def __init__(self, server_id, conf_dir, public=None, bind=None, prom_export=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param list public:
            (host_addr, port) of the element's public address
            (i.e. the address visible to other network elements).
        :param list bind:
            (host_addr, port) of the element's bind address, if any
            (i.e. the address the element uses to identify itself to the local
            operating system, if it differs from the public address due to NAT).
        :param str prom_export:
            String of the form 'addr:port' specifying the prometheus endpoint.
            If no string is provided, no metrics are exported.
        """
        self.id = server_id
        self.conf_dir = conf_dir
        self.ifid2br = {}
        self.topology = Topology.from_file(
            os.path.join(self.conf_dir, TOPO_FILE))
        self.config = Config.from_file(
            os.path.join(self.conf_dir, AS_CONF_FILE))
        # Labels attached to every exported metric.
        self._labels = {"server_id": self.id, "isd_as": str(self.topology.isd_as)}
        # Must be over-ridden by child classes:
        self.CTRL_PLD_CLASS_MAP = {}
        self.SCMP_PLD_CLASS_MAP = {}
        self.public = public
        self.bind = bind
        if self.SERVICE_TYPE:
            own_config = self.topology.get_own_config(self.SERVICE_TYPE,
                                                      server_id)
            if public is None:
                self.public = own_config.public
            if bind is None:
                self.bind = own_config.bind
        self.init_ifid2br()
        self.trust_store = TrustStore(self.conf_dir, GEN_CACHE_PATH, self.id, self._labels)
        self.total_dropped = 0
        self._core_ases = defaultdict(list)  # Mapping ISD_ID->list of core ASes
        self.init_core_ases()
        self.run_flag = threading.Event()
        self.run_flag.set()
        self.stopped_flag = threading.Event()
        self.stopped_flag.clear()
        self._in_buf = queue.Queue(MAX_QUEUE)
        self._socks = SocketMgr()
        self._startup = time.time()
        if self.USE_TCP:
            self._DefaultMeta = TCPMetadata
        else:
            self._DefaultMeta = UDPMetadata
        self.unverified_segs = ExpiringDict(500, 60 * 60)
        self.unv_segs_lock = threading.RLock()
        self.requested_trcs = {}
        self.req_trcs_lock = threading.Lock()
        self.requested_certs = {}
        self.req_certs_lock = threading.Lock()
        # TODO(jonghoonkwon): Fix me to setup sockets for multiple public addresses
        host_addr, self._port = self.public[0]
        self.addr = SCIONAddr.from_values(self.topology.isd_as, host_addr)
        if prom_export:
            self._export_metrics(prom_export)
            self._init_metrics()
        self._setup_sockets(True)
        lib_sciond.init(os.path.join(SCIOND_API_SOCKDIR, "sd%s.sock" % self.addr.isd_as))

    def _setup_sockets(self, init):
        """
        Setup incoming socket and register with dispatcher
        """
        self._tcp_sock = None
        self._tcp_new_conns = queue.Queue(MAX_QUEUE)  # New TCP connections.
        if self._port is None:
            # No scion socket desired.
            return
        svc = SERVICE_TO_SVC_A.get(self.SERVICE_TYPE)
        # Setup TCP "accept" socket.
        self._setup_tcp_accept_socket(svc)
        # Setup UDP socket
        if self.bind:
            # TODO(jonghoonkwon): Fix me to setup socket for a proper bind address,
            # if the element has more than one bind addresses
            host_addr, b_port = self.bind[0]
            b_addr = SCIONAddr.from_values(self.topology.isd_as, host_addr)
            self._udp_sock = ReliableSocket(
                reg=(self.addr, self._port, init, svc), bind_ip=(b_addr, b_port))
        else:
            self._udp_sock = ReliableSocket(
                reg=(self.addr, self._port, init, svc))
        if not self._udp_sock.registered:
            self._udp_sock = None
            return
        if self._labels:
            CONNECTED_TO_DISPATCHER.labels(**self._labels).set(1)
        self._port = self._udp_sock.port
        self._socks.add(self._udp_sock, self.handle_recv)

    def _setup_tcp_accept_socket(self, svc):
        if not self.USE_TCP:
            return
        MAX_TRIES = 40
        for i in range(MAX_TRIES):
            try:
                self._tcp_sock = SCIONTCPSocket()
                self._tcp_sock.setsockopt(SockOpt.SOF_REUSEADDR)
                self._tcp_sock.set_recv_tout(TCP_ACCEPT_POLLING_TOUT)
                self._tcp_sock.bind((self.addr, self._port), svc=svc)
                self._tcp_sock.listen()
                break
            except SCIONTCPError as e:
                logging.warning("TCP: Cannot connect to LWIP socket: %s" % e)
            time.sleep(1)  # Wait for dispatcher
        else:
            logging.critical("TCP: cannot init TCP socket.")
            kill_self()

    def init_ifid2br(self):
        for br in self.topology.border_routers:
            for if_id in br.interfaces:
                self.ifid2br[if_id] = br

    def init_core_ases(self):
        """
        Initializes dict of core ASes.
        """
        for trc in self.trust_store.get_trcs():
            self._core_ases[trc.isd] = trc.get_core_ases()

    def is_core_as(self, isd_as=None):
        if not isd_as:
            isd_as = self.addr.isd_as
        return isd_as in self._core_ases[isd_as[0]]

    def _update_core_ases(self, trc):
        """
        When a new trc is received, this function is called to
        update the core ases map
        """
        self._core_ases[trc.isd] = trc.get_core_ases()

    def get_border_addr(self, ifid):
        br = self.ifid2br[ifid]
        addr_idx = br.interfaces[ifid].addr_idx
        br_addr, br_port = br.int_addrs[addr_idx].public[0]
        return br_addr, br_port

    def handle_msg_meta(self, msg, meta):
        """
        Main routine to handle incoming SCION messages.
        """
        if isinstance(meta, SCMPMetadata):
            handler = self._get_scmp_handler(meta.pkt)
        else:
            handler = self._get_ctrl_handler(msg)
        if not handler:
            logging.error("handler not found: %s", msg)
            return
        try:
            # SIBRA operates on parsed packets.
            if (isinstance(meta, UDPMetadata) and msg.type() == PayloadClass.SIBRA):
                handler(meta.pkt)
            else:
                handler(msg, meta)
        except SCIONBaseError:
            log_exception("Error handling message:\n%s" % msg)

    def _check_trc_cert_reqs(self):
        check_cyle = 1.0
        while self.run_flag.is_set():
            start = time.time()
            self._check_cert_reqs()
            self._check_trc_reqs()
            sleep_interval(start, check_cyle, "Elem._check_trc_cert_reqs cycle")

    def _check_trc_reqs(self):
        """
        Checks if TRC requests timeout and resends requests if so.
        """
        with self.req_trcs_lock:
            now = time.time()
            for (isd, ver), (req_time, meta) in self.requested_trcs.items():
                if now - req_time >= self.TRC_CC_REQ_TIMEOUT:
                    trc_req = TRCRequest.from_values(isd, ver, cache_only=True)
                    meta = meta or self._get_cs()
                    logging.info("Re-Requesting TRC from %s: %s", meta, trc_req.short_desc())
                    self.send_meta(CtrlPayload(CertMgmt(trc_req)), meta)
                    self.requested_trcs[(isd, ver)] = (time.time(), meta)
                    if self._labels:
                        PENDING_TRC_REQS_TOTAL.labels(**self._labels).set(len(self.requested_trcs))

    def _check_cert_reqs(self):
        """
        Checks if certificate requests timeout and resends requests if so.
        """
        with self.req_certs_lock:
            now = time.time()
            for (isd_as, ver), (req_time, meta) in self.requested_certs.items():
                if now - req_time >= self.TRC_CC_REQ_TIMEOUT:
                    cert_req = CertChainRequest.from_values(isd_as, ver, cache_only=True)
                    meta = meta or self._get_cs()
                    logging.info("Re-Requesting CERTCHAIN from %s: %s", meta, cert_req.short_desc())
                    self.send_meta(CtrlPayload(CertMgmt(cert_req)), meta)
                    self.requested_certs[(isd_as, ver)] = (time.time(), meta)
                    if self._labels:
                        PENDING_CERT_REQS_TOTAL.labels(**self._labels).set(
                            len(self.requested_certs))

    def _process_path_seg(self, seg_meta):
        """
        When a pcb or path segment is received, this function is called to
        find missing TRCs and certs and request them.
        :param seg_meta: PathSegMeta object that contains pcb/path segment
        """
        meta_str = str(seg_meta.meta) if seg_meta.meta else "ZK"
        logging.debug("Handling PCB from %s: %s" % (meta_str, seg_meta.seg.short_desc()))
        with self.unv_segs_lock:
            # Close the meta of the previous seg_meta, if there was one.
            prev_meta = self.unverified_segs.get(seg_meta.id)
            if prev_meta and prev_meta.meta:
                prev_meta.meta.close()
            self.unverified_segs[seg_meta.id] = seg_meta
            if self._labels:
                UNV_SEGS_TOTAL.labels(**self._labels).set(len(self.unverified_segs))
        # Find missing TRCs and certificates
        missing_trcs = self._missing_trc_versions(seg_meta.trc_vers)
        missing_certs = self._missing_cert_versions(seg_meta.cert_vers)
        # Update missing TRCs/certs map
        seg_meta.missing_trcs.update(missing_trcs)
        seg_meta.missing_certs.update(missing_certs)
        # If all necessary TRCs/certs available, try to verify
        if seg_meta.verifiable():
            self._try_to_verify_seg(seg_meta)
            return
        # Otherwise request missing trcs, certs
        self._request_missing_trcs(seg_meta)
        self._request_missing_certs(seg_meta)
        if seg_meta.meta:
            seg_meta.meta.close()

    def _try_to_verify_seg(self, seg_meta):
        """
        If this pcb/path segment can be verified, call the function
        to process a verified pcb/path segment
        """
        try:
            self._verify_path_seg(seg_meta)
        except SCIONVerificationError as e:
            logging.error("Signature verification failed for %s: %s" %
                          (seg_meta.seg.short_id(), e))
            return
        with self.unv_segs_lock:
            self.unverified_segs.pop(seg_meta.id, None)
            if self._labels:
                UNV_SEGS_TOTAL.labels(**self._labels).set(len(self.unverified_segs))
        if seg_meta.meta:
            seg_meta.meta.close()
        seg_meta.callback(seg_meta)

    def _get_cs(self):
        """
        Lookup certificate servers address and return meta.
        """
        try:
            addr, port = self.dns_query_topo(CERTIFICATE_SERVICE)[0]
        except SCIONServiceLookupError as e:
            logging.warning("Lookup for certificate service failed: %s", e)
            return None
        return UDPMetadata.from_values(host=addr, port=port)

    def _request_missing_trcs(self, seg_meta):
        """
        For all missing TRCs which are missing to verify this pcb/path segment,
        request them. Request is sent to certificate server, if the
        pcb/path segment was received by zk. Otherwise the sender of this
        pcb/path segment is asked.
        """
        missing_trcs = set()
        with seg_meta.miss_trc_lock:
            missing_trcs = seg_meta.missing_trcs.copy()
        if not missing_trcs:
            return
        for isd, ver in missing_trcs:
            with self.req_trcs_lock:
                req_time, meta = self.requested_trcs.get((isd, ver), (None, None))
                if meta:
                    # There is already an outstanding request for the missing TRC
                    # from somewhere else than than the local CS
                    if seg_meta.meta:
                        # Update the stored meta with the latest known server that has the TRC.
                        self.requested_trcs[(isd, ver)] = (req_time, seg_meta.meta)
                    continue
                if req_time and not seg_meta.meta:
                    # There is already an outstanding request for the missing TRC
                    # to the local CS and we don't have a new meta.
                    continue
            trc_req = TRCRequest.from_values(isd, ver, cache_only=True)
            meta = seg_meta.meta or self._get_cs()
            if not meta:
                logging.error("Couldn't find a CS to request TRC for PCB %s",
                              seg_meta.seg.short_id())
                continue
            logging.info("Requesting %sv%s TRC from %s, for PCB %s",
                         isd, ver, meta, seg_meta.seg.short_id())
            with self.req_trcs_lock:
                self.requested_trcs[(isd, ver)] = (time.time(), seg_meta.meta)
                if self._labels:
                    PENDING_TRC_REQS_TOTAL.labels(**self._labels).set(len(self.requested_trcs))
            self.send_meta(CtrlPayload(CertMgmt(trc_req)), meta)

    def _request_missing_certs(self, seg_meta):
        """
        For all missing CCs which are missing to verify this pcb/path segment,
        request them. Request is sent to certificate server, if the
        pcb/path segment was received by zk. Otherwise the sender of this
        pcb/path segment is asked.
        """
        missing_certs = set()
        with seg_meta.miss_cert_lock:
            missing_certs = seg_meta.missing_certs.copy()
        if not missing_certs:
            return
        for isd_as, ver in missing_certs:
            with self.req_certs_lock:
                req_time, meta = self.requested_certs.get((isd_as, ver), (None, None))
                if meta:
                    # There is already an outstanding request for the missing cert
                    # from somewhere else than than the local CS
                    if seg_meta.meta:
                        # Update the stored meta with the latest known server that has the cert.
                        self.requested_certs[(isd_as, ver)] = (req_time, seg_meta.meta)
                    continue
                if req_time and not seg_meta.meta:
                    # There is already an outstanding request for the missing cert
                    # to the local CS and we don't have a new meta.
                    continue
            cert_req = CertChainRequest.from_values(isd_as, ver, cache_only=True)
            meta = seg_meta.meta or self._get_cs()
            if not meta:
                logging.error("Couldn't find a CS to request CERTCHAIN for PCB %s",
                              seg_meta.seg.short_id())
                continue
            logging.info("Requesting %sv%s CERTCHAIN from %s for PCB %s",
                         isd_as, ver, meta, seg_meta.seg.short_id())
            with self.req_certs_lock:
                self.requested_certs[(isd_as, ver)] = (time.time(), seg_meta.meta)
                if self._labels:
                    PENDING_CERT_REQS_TOTAL.labels(**self._labels).set(len(self.requested_certs))
            self.send_meta(CtrlPayload(CertMgmt(cert_req)), meta)

    def _missing_trc_versions(self, trc_versions):
        """
        Check which intermediate trcs are missing and return their versions.
        :returns: the missing TRCs'
        :rtype set
        """
        missing_trcs = set()
        for isd, versions in trc_versions.items():
            # If not local TRC, only request versions contained in ASMarkings
            if isd is not self.topology.isd_as[0]:
                for ver in versions:
                    if self.trust_store.get_trc(isd, ver) is None:
                        missing_trcs.add((isd, ver))
                continue
            # Local TRC
            max_req_ver = max(versions)
            max_local_ver = self.trust_store.get_trc(isd)
            lower_ver = 0
            if max_local_ver is None:
                # This should never happen
                logging.critical("Local TRC not found!")
                kill_self()
            lower_ver = max_local_ver.version + 1
            for ver in range(lower_ver, max_req_ver + 1):
                missing_trcs.add((isd, ver))
        return missing_trcs

    def _missing_cert_versions(self, cert_versions):
        """
        Check which and certificates are missing return their versions.
        :returns: the missing certs' versions
        :rtype set
        """
        missing_certs = set()
        for isd_as, versions in cert_versions.items():
            for ver in versions:
                if self.trust_store.get_cert(isd_as, ver) is None:
                    missing_certs.add((isd_as, ver))
        return missing_certs

    def process_trc_reply(self, cpld, meta):
        """
        Process the TRC reply.
        :param rep: TRC reply.
        :type rep: TRCReply.
        """
        meta.close()
        cmgt = cpld.union
        rep = cmgt.union
        assert isinstance(rep, TRCReply), type(rep)
        isd, ver = rep.trc.get_isd_ver()
        logging.info("TRC reply received for %sv%s from %s" % (isd, ver, meta))
        self.trust_store.add_trc(rep.trc, True)
        # Update core ases for isd this trc belongs to
        max_local_ver = self.trust_store.get_trc(rep.trc.isd)
        if max_local_ver.version == rep.trc.version:
            self._update_core_ases(rep.trc)
        with self.req_trcs_lock:
            self.requested_trcs.pop((isd, ver), None)
            if self._labels:
                PENDING_TRC_REQS_TOTAL.labels(**self._labels).set(len(self.requested_trcs))
        # Send trc to CS
        if meta.get_addr().isd_as != self.addr.isd_as:
            cs_meta = self._get_cs()
            self.send_meta(CtrlPayload(CertMgmt(rep)), cs_meta)
            cs_meta.close()
        # Remove received TRC from map
        self._check_segs_with_rec_trc(isd, ver)

    def _check_segs_with_rec_trc(self, isd, ver):
        """
        When a trc reply is received, this method is called to check which
        segments can be verified. For all segments that can be verified,
        the processing is continued.
        """
        with self.unv_segs_lock:
            for seg_meta in list(self.unverified_segs.values()):
                with seg_meta.miss_trc_lock:
                    seg_meta.missing_trcs.discard((isd, ver))
                # If all required trcs and certs are received
                if seg_meta.verifiable():
                    self._try_to_verify_seg(seg_meta)

    def process_trc_request(self, cpld, meta):
        """Process a TRC request."""
        cmgt = cpld.union
        req = cmgt.union
        assert isinstance(req, TRCRequest), type(req)
        isd, ver = req.isd_as()[0], req.p.version
        logging.info("TRC request received for %sv%s from %s" % (isd, ver, meta))
        trc = self.trust_store.get_trc(isd, ver)
        if trc:
            self.send_meta(CtrlPayload(CertMgmt(TRCReply.from_values(trc))), meta)
        else:
            logging.warning("Could not find requested TRC %sv%s" % (isd, ver))

    def process_cert_chain_reply(self, cpld, meta):
        """Process a certificate chain reply."""
        cmgt = cpld.union
        rep = cmgt.union
        assert isinstance(rep, CertChainReply), type(rep)
        meta.close()
        isd_as, ver = rep.chain.get_leaf_isd_as_ver()
        logging.info("Cert chain reply received for %sv%s from %s" % (isd_as, ver, meta))
        self.trust_store.add_cert(rep.chain, True)
        with self.req_certs_lock:
            self.requested_certs.pop((isd_as, ver), None)
            if self._labels:
                PENDING_CERT_REQS_TOTAL.labels(**self._labels).set(len(self.requested_certs))
        # Send cc to CS
        if meta.get_addr().isd_as != self.addr.isd_as:
            cs_meta = self._get_cs()
            self.send_meta(CtrlPayload(CertMgmt(rep)), cs_meta)
            cs_meta.close()
        # Remove received cert chain from map
        self._check_segs_with_rec_cert(isd_as, ver)

    def _check_segs_with_rec_cert(self, isd_as, ver):
        """
        When a CC reply is received, this method is called to check which
        segments can be verified. For all segments that can be verified,
        the processing is continued.
        """
        with self.unv_segs_lock:
            for seg_meta in list(self.unverified_segs.values()):
                with seg_meta.miss_cert_lock:
                    seg_meta.missing_certs.discard((isd_as, ver))
                # If all required trcs and certs are received.
                if seg_meta.verifiable():
                    self._try_to_verify_seg(seg_meta)

    def process_cert_chain_request(self, cpld, meta):
        """Process a certificate chain request."""
        cmgt = cpld.union
        req = cmgt.union
        assert isinstance(req, CertChainRequest), type(req)
        isd_as, ver = req.isd_as(), req.p.version
        logging.info("Cert chain request received for %sv%s from %s" % (isd_as, ver, meta))
        cert = self.trust_store.get_cert(isd_as, ver)
        if cert:
            self.send_meta(CtrlPayload(CertMgmt(CertChainReply.from_values(cert))), meta)
        else:
            logging.warning("Could not find requested certificate %sv%s" %
                            (isd_as, ver))

    def _verify_path_seg(self, seg_meta):
        """
        Signature verification for all AS markings within this pcb/path segment.
        This function is called, when all TRCs and CCs used within this pcb/path
        segment are available.
        """
        seg = seg_meta.seg
        exp_time = seg.get_expiration_time()
        for i, asm in enumerate(seg.iter_asms()):
            cert_ia = asm.isd_as()
            trc = self.trust_store.get_trc(cert_ia[0], asm.p.trcVer)
            chain = self.trust_store.get_cert(asm.isd_as(), asm.p.certVer)
            self._verify_exp_time(exp_time, chain)
            verify_chain_trc(cert_ia, chain, trc)
            seg.verify(chain.as_cert.subject_sig_key_raw, i)

    def _verify_exp_time(self, exp_time, chain):
        """
        Verify that certificate chain cover the expiration time.
        :raises SCIONVerificationError
        """
        # chain is only verifiable if TRC.exp_time >= CoreCert.exp_time >= LeafCert.exp_time
        if chain.as_cert.expiration_time < exp_time:
            raise SCIONVerificationError(
                "Certificate chain %sv%s expires before path segment" % chain.get_leaf_isd_as_ver())

    def _get_ctrl_handler(self, msg):
        pclass = msg.type()
        try:
            type_map = self.CTRL_PLD_CLASS_MAP[pclass]
        except KeyError:
            logging.error("Control payload class not supported: %s\n%s", pclass, msg)
            return None
        ptype = msg.inner_type()
        try:
            return type_map[ptype]
        except KeyError:
            logging.error("%s control payload type not supported: %s\n%s", pclass, ptype, msg)
        return None

    def _get_scmp_handler(self, pkt):
        scmp = pkt.l4_hdr
        try:
            type_map = self.SCMP_PLD_CLASS_MAP[scmp.class_]
        except KeyError:
            logging.error("SCMP class not supported: %s(%s)\n%s",
                          scmp.class_, SCMPClass.to_str(scmp.class_), pkt)
            return None
        try:
            return type_map[scmp.type]
        except KeyError:
            logging.error("SCMP %s type not supported: %s(%s)\n%s", scmp.type,
                          scmp.class_, scmp_type_name(scmp.class_, scmp.type), pkt)
        return None

    def _parse_packet(self, packet):
        try:
            pkt = SCIONL4Packet(packet)
        except SCMPError as e:
            self._scmp_parse_error(packet, e)
            return None
        except SCIONBaseError:
            log_exception("Error parsing packet: %s" % hex_str(packet),
                          level=logging.ERROR)
            return None
        try:
            pkt.validate(len(packet))
        except SCMPError as e:
            self._scmp_validate_error(pkt, e)
            return None
        except SCIONChecksumFailed:
            logging.debug("Dropping packet due to failed checksum:\n%s", pkt)
        return pkt

    def _scmp_parse_error(self, packet, e):
        HDR_TYPE_OFFSET = 6
        if packet[HDR_TYPE_OFFSET] == L4Proto.SCMP:
            # Ideally, never respond to an SCMP error with an SCMP error.
            # However, if parsing failed, we can (at best) only determine if
            # it's an SCMP packet, so just drop SCMP packets on parse error.
            logging.warning("Dropping SCMP packet due to parse error. %s", e)
            return
        # For now, none of these can be properly handled, so just log and drop
        # the packet. In the future, the "x Not Supported" errors might be
        # handlable in the case of deprecating old versions.
        DROP = SCMPBadVersion, SCMPBadSrcType, SCMPBadDstType
        assert isinstance(e, DROP), type(e)
        logging.warning("Dropping packet due to parse error: %s", e)

    def _scmp_validate_error(self, pkt, e):
        if pkt.cmn_hdr.next_hdr == L4Proto.SCMP and pkt.ext_hdrs[0].error:
            # Never respond to an SCMP error with an SCMP error.
            logging.info(
                "Dropping SCMP error packet due to validation error. %s", e)
            return
        if isinstance(e, (SCMPBadIOFOffset, SCMPBadHOFOffset)):
            # Can't handle normally, as the packet isn't reversible.
            reply = self._scmp_bad_path_metadata(pkt, e)
        else:
            logging.warning("Error: %s", type(e))
            reply = pkt.reversed_copy()
            args = ()
            if isinstance(e, SCMPUnspecified):
                args = (str(e),)
            elif isinstance(e, (SCMPOversizePkt, SCMPBadPktLen)):
                args = (e.args[1],)  # the relevant MTU.
            elif isinstance(e, (SCMPTooManyHopByHop, SCMPBadExtOrder,
                                SCMPBadHopByHop)):
                args = e.args
                if isinstance(e, SCMPBadExtOrder):
                    # Delete the problematic extension.
                    del reply.ext_hdrs[args[0]]
            reply.convert_to_scmp_error(self.addr, e.CLASS, e.TYPE, pkt, *args)
        if pkt.addrs.src.isd_as == self.addr.isd_as:
            # No path needed for a local reply.
            reply.path = SCIONPath()
        next_hop, port = self.get_first_hop(reply)
        reply.update()
        self.send(reply, next_hop, port)

    def _scmp_bad_path_metadata(self, pkt, e):
        """
        Handle a packet with an invalid IOF/HOF offset in the common header.

        As the path can't be used, a response can only be sent if the source is
        local (as that doesn't require a path).
        """
        if pkt.addrs.src.isd_as != self.addr.isd_as:
            logging.warning(
                "Invalid path metadata in packet from "
                "non-local source, dropping: %s\n%s\n%s\n%s",
                e, pkt.cmn_hdr, pkt.addrs, pkt.path)
            return
        reply = copy.deepcopy(pkt)
        # Remove existing path before reversing.
        reply.path = SCIONPath()
        reply.reverse()
        reply.convert_to_scmp_error(self.addr, e.CLASS, e.TYPE, pkt)
        reply.update()
        logging.warning(
            "Invalid path metadata in packet from "
            "local source, sending SCMP error: %s\n%s\n%s\n%s",
            e, pkt.cmn_hdr, pkt.addrs, pkt.path)
        return reply

    def get_first_hop(self, spkt):
        """
        Returns first hop addr of down-path or end-host addr.
        """
        return self._get_first_hop(spkt.path, spkt.addrs.dst, spkt.ext_hdrs)

    def _get_first_hop(self, path, dst, ext_hdrs=()):
        if_id = self._ext_first_hop(ext_hdrs)
        if if_id is None:
            if len(path) == 0:
                return self._empty_first_hop(dst)
            if_id = path.get_fwd_if()
        if if_id in self.ifid2br:
            return self.get_border_addr(if_id)
        logging.error("Unable to find first hop:\n%s", path)
        return None, None

    def _ext_first_hop(self, ext_hdrs):
        for hdr in ext_hdrs:
            if_id = hdr.get_next_ifid()
            if if_id is not None:
                return if_id

    def _empty_first_hop(self, dst):
        if dst.isd_as != self.addr.isd_as:
            logging.error("Packet to remote AS w/o path, dst: %s", dst)
            return None, None
        host = dst.host
        if host.TYPE == AddrType.SVC:
            host = self.dns_query_topo(SVC_TO_SERVICE[host.addr])[0][0]
        return host, SCION_UDP_EH_DATA_PORT

    def _build_packet(self, dst_host=None, path=None, ext_hdrs=(),
                      dst_ia=None, payload=None, dst_port=0):
        if dst_host is None:
            dst_host = HostAddrNone()
        if dst_ia is None:
            dst_ia = self.addr.isd_as
        if path is None:
            path = SCIONPath()
        if payload is None:
            payload = PayloadRaw()
        dst_addr = SCIONAddr.from_values(dst_ia, dst_host)
        cmn_hdr, addr_hdr = build_base_hdrs(dst_addr, self.addr)
        udp_hdr = SCIONUDPHeader.from_values(
            self.addr, self._port, dst_addr, dst_port)
        return SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, path, ext_hdrs, udp_hdr, payload)

    def send(self, packet, dst, dst_port):
        """
        Send *packet* to *dst* (to port *dst_port*) using the local socket.
        Calling ``packet.pack()`` should return :class:`bytes`, and
        ``dst.__str__()`` should return a string representing an IP address.

        :param packet: the packet to be sent to the destination.
        :param str dst: the destination IP address.
        :param int dst_port: the destination port number.
        """
        assert not isinstance(packet.addrs.src.host, HostAddrNone), type(packet.addrs.src.host)
        assert not isinstance(packet.addrs.dst.host, HostAddrNone), type(packet.addrs.dst.host)
        assert isinstance(packet, SCIONBasePacket), type(packet)
        assert isinstance(dst_port, int), type(dst_port)
        if not self._udp_sock:
            return False
        return self._udp_sock.send(packet.pack(), (dst, dst_port))

    def send_meta(self, msg, meta, next_hop_port=None):
        if isinstance(meta, TCPMetadata):
            assert not next_hop_port, next_hop_port
            return self._send_meta_tcp(msg, meta)
        elif isinstance(meta, SockOnlyMetadata):
            assert not next_hop_port, next_hop_port
            return meta.sock.send(msg)
        elif isinstance(meta, UDPMetadata):
            dst_port = meta.port
        else:
            logging.error("Unsupported metadata: %s" % meta.__name__)
            return False

        pkt = self._build_packet(meta.host, meta.path, meta.ext_hdrs,
                                 meta.ia, msg, dst_port)
        if not next_hop_port:
            next_hop_port = self.get_first_hop(pkt)
        if next_hop_port == (None, None):
            logging.error("Can't find first hop, dropping packet\n%s", pkt)
            return False
        return self.send(pkt, *next_hop_port)

    def _send_meta_tcp(self, msg, meta):
        if not meta.sock:
            tcp_sock = self._tcp_sock_from_meta(meta)
            meta.sock = tcp_sock
            self._tcp_conns_put(tcp_sock)
        return meta.sock.send_msg(msg.pack())

    def _tcp_sock_from_meta(self, meta):
        assert meta.host
        dst = meta.get_addr()
        first_ip, first_port = self._get_first_hop(meta.path, dst)
        active = True
        try:
            # Create low-level TCP socket and connect
            sock = SCIONTCPSocket()
            sock.bind((self.addr, 0))
            sock.connect(dst, meta.port, meta.path, first_ip, first_port,
                         flags=meta.flags)
        except SCIONTCPError:
            log_exception("TCP: connection init error, marking socket inactive")
            sock = None
            active = False
        # Create and return TCPSocketWrapper
        return TCPSocketWrapper(sock, dst, meta.path, active)

    def _tcp_conns_put(self, sock):
        dropped = 0
        while True:
            try:
                self._tcp_new_conns.put(sock, block=False)
            except queue.Full:
                old_sock = self._tcp_new_conns.get_nowait()
                old_sock.close()
                logging.error("TCP: _tcp_new_conns is full. Closing old socket")
                dropped += 1
            else:
                break
        if dropped > 0:
            logging.warning("%d TCP connection(s) dropped" % dropped)

    def run(self):
        """
        Main routine to receive packets and pass them to
        :func:`handle_request()`.
        """
        self._tcp_start()
        threading.Thread(
            target=thread_safety_net, args=(self.packet_recv,),
            name="Elem.packet_recv", daemon=True).start()
        try:
            self._packet_process()
        except SCIONBaseError:
            log_exception("Error processing packet.")
        finally:
            self.stop()

    def packet_put(self, packet, addr, sock):
        """
        Try to put incoming packet in queue
        If queue is full, drop oldest packet in queue
        """
        msg, meta = self._get_msg_meta(packet, addr, sock)
        if msg is None:
            return
        self._in_buf_put((msg, meta))

    def _in_buf_put(self, item):
        dropped = 0
        while True:
            try:
                self._in_buf.put(item, block=False)
                if self._labels:
                    PKT_BUF_BYTES.labels(**self._labels).inc(len(item[0]))
            except queue.Full:
                msg, _ = self._in_buf.get_nowait()
                dropped += 1
                if self._labels:
                    PKTS_DROPPED_TOTAL.labels(**self._labels).inc()
                    PKT_BUF_BYTES.labels(**self._labels).dec(len(msg))
            else:
                break
            finally:
                if self._labels:
                    PKT_BUF_TOTAL.labels(**self._labels).set(self._in_buf.qsize())
        if dropped > 0:
            self.total_dropped += dropped
            logging.warning("%d packet(s) dropped (%d total dropped so far)",
                            dropped, self.total_dropped)

    def _get_msg_meta(self, packet, addr, sock):
        pkt = self._parse_packet(packet)
        if not pkt:
            logging.error("Cannot parse packet:\n%s" % packet)
            return None, None
        # Create metadata:
        rev_pkt = pkt.reversed_copy()
        # Skip OneHopPathExt (if exists)
        exts = []
        for e in rev_pkt.ext_hdrs:
            if not isinstance(e, OneHopPathExt):
                exts.append(e)
        if rev_pkt.l4_hdr.TYPE == L4Proto.UDP:
            meta = UDPMetadata.from_values(ia=rev_pkt.addrs.dst.isd_as,
                                           host=rev_pkt.addrs.dst.host,
                                           path=rev_pkt.path,
                                           ext_hdrs=exts,
                                           port=rev_pkt.l4_hdr.dst_port)
        elif rev_pkt.l4_hdr.TYPE == L4Proto.SCMP:
            meta = SCMPMetadata.from_values(ia=rev_pkt.addrs.dst.isd_as,
                                            host=rev_pkt.addrs.dst.host,
                                            path=rev_pkt.path,
                                            ext_hdrs=exts)

        else:
            logging.error("Cannot create meta for: %s" % pkt)
            return None, None

        # FIXME(PSz): for now it is needed by SIBRA service.
        meta.pkt = pkt
        try:
            pkt.parse_payload()
        except SCIONParseError as e:
            logging.error("Cannot parse payload\n  Error: %s\n  Pkt: %s", e, pkt)
            return None, meta
        return pkt.get_payload(), meta

    def handle_accept(self, sock):
        """
        Callback to handle a ready listening socket
        """
        s = sock.accept()
        if not s:
            logging.error("accept failed")
            return
        self._socks.add(s, self.handle_recv)

    def handle_recv(self, sock):
        """
        Callback to handle a ready recving socket
        """
        packet, addr = sock.recv()
        if packet is None:
            self._socks.remove(sock)
            sock.close()
            if sock == self._udp_sock:
                self._udp_sock = None
                if self._labels:
                    CONNECTED_TO_DISPATCHER.labels(**self._labels).set(0)
            return
        self.packet_put(packet, addr, sock)

    def packet_recv(self):
        """
        Read packets from sockets, and put them into a :class:`queue.Queue`.
        """
        while self.run_flag.is_set():
            if not self._udp_sock:
                self._setup_sockets(False)
            for sock, callback in self._socks.select_(timeout=0.1):
                callback(sock)
            self._tcp_socks_update()
        self._socks.close()
        self.stopped_flag.set()

    def _packet_process(self):
        """
        Read packets from a :class:`queue.Queue`, and process them.
        """
        while self.run_flag.is_set():
            try:
                msg, meta = self._in_buf.get(timeout=1.0)
                if self._labels:
                    PKT_BUF_BYTES.labels(**self._labels).dec(len(msg))
                    PKT_BUF_TOTAL.labels(**self._labels).set(self._in_buf.qsize())
                self.handle_msg_meta(msg, meta)
            except queue.Empty:
                continue

    def _tcp_start(self):
        if not self.USE_TCP:
            return
        if not self._tcp_sock:
            logging.warning("TCP: accept socket is unset, port:%d", self._port)
            return
        threading.Thread(
            target=thread_safety_net, args=(self._tcp_accept_loop,),
            name="Elem._tcp_accept_loop", daemon=True).start()

    def _tcp_accept_loop(self):
        while self.run_flag.is_set():
            try:
                logging.debug("TCP: waiting for connections")
                self._tcp_conns_put(TCPSocketWrapper(*self._tcp_sock.accept()))
                logging.debug("TCP: accepted connection")
            except SCIONTCPTimeout:
                pass
            except SCIONTCPError:
                log_exception("TCP: error on accept()")
                logging.error("TCP: leaving the accept loop")
                break
        try:
            self._tcp_sock.close()
        except SCIONTCPError:
            log_exception("TCP: error on closing _tcp_sock")

    def _tcp_socks_update(self):
        if not self.USE_TCP:
            return
        self._socks.remove_inactive()
        self._tcp_add_waiting()

    def _tcp_add_waiting(self):
        while True:
            try:
                self._socks.add(self._tcp_new_conns.get_nowait(),
                                self._tcp_handle_recv)
            except queue.Empty:
                break

    def _tcp_handle_recv(self, sock):
        """
        Callback to handle a ready recving socket
        """
        msg, meta = sock.get_msg_meta()
        logging.debug("tcp_handle_recv:%s, %s", msg, meta)
        if msg is None and meta is None:
            self._socks.remove(sock)
            sock.close()
            return
        if msg:
            self._in_buf_put((msg, meta))

    def _tcp_clean(self):
        if not hasattr(self, "_tcp_sock") or not self._tcp_sock:
            return
        # Close all TCP sockets.
        while not self._tcp_new_conns.empty():
            try:
                tcp_sock = self._tcp_new_conns.get_nowait()
            except queue.Empty:
                break
            tcp_sock.close()

    def stop(self):
        """Shut down the daemon thread."""
        # Signal that the thread should stop
        self.run_flag.clear()
        # Wait for the thread to finish
        self.stopped_flag.wait(5)
        # Close tcp sockets.
        self._tcp_clean()

    def _quiet_startup(self):
        return (time.time() - self._startup) < self.STARTUP_QUIET_PERIOD

    def dns_query_topo(self, qname):
        """
        Query dns for an answer. If the answer is empty, or an error occurs then
        return the relevant topology entries instead.

        :param str qname: Service to query for.
        """
        assert qname in SERVICE_TYPES
        service_map = {
            BEACON_SERVICE: self.topology.beacon_servers,
            CERTIFICATE_SERVICE: self.topology.certificate_servers,
            PATH_SERVICE: self.topology.path_servers,
            SIBRA_SERVICE: self.topology.sibra_servers,
        }
        # Generate fallback from local topology
        results = []
        for srv in service_map[qname]:
            addr, port = srv.public[0]
            results.append((addr, port))
        # FIXME(kormat): replace with new discovery service when that's ready.
        if not results:
            # No results from local toplogy either
            raise SCIONServiceLookupError("No %s servers found" % qname)
        return results

    def _verify_revocation_for_asm(self, rev_info, as_marking, verify_all=True):
        """
        Verifies a revocation for a given AS marking.

        :param rev_info: The RevocationInfo object.
        :param as_marking: The ASMarking object.
        :param verify_all: If true, verify all PCBMs (including peers),
            otherwise only verify the up/down hop.
        :return: True, if the revocation successfully revokes an upstream
            interface in the AS marking, False otherwise.
        """
        if rev_info.isd_as() != as_marking.isd_as():
            return False
        if not ConnectedHashTree.verify(rev_info, as_marking.p.hashTreeRoot):
            logging.error("Revocation verification failed. %s", rev_info)
            return False
        for pcbm in as_marking.iter_pcbms():
            if rev_info.p.ifID in [pcbm.hof().ingress_if, pcbm.hof().egress_if]:
                return True
            if not verify_all:
                break
        return False

    def _build_meta(self, ia=None, host=None, path=None, port=0, reuse=False,
                    one_hop=False):
        if ia is None:
            ia = self.addr.isd_as
        if path is None:
            path = SCIONPath()
        if not one_hop:
            return self._DefaultMeta.from_values(ia, host, path, port=port,
                                                 reuse=reuse)
        # One hop path extension in handled in a different way in TCP and UDP
        if self._DefaultMeta == TCPMetadata:
            return TCPMetadata.from_values(ia, host, path, port=port, reuse=reuse,
                                           flags=TCPFlags.ONEHOPPATH)
        return UDPMetadata.from_values(ia, host, path, port=port, reuse=reuse,
                                       ext_hdrs=[OneHopPathExt()])

    def _export_metrics(self, export_addr):
        """
        Starts an HTTP server endpoint for prometheus to scrape.
        """
        addr, port = export_addr.split(":")
        port = int(port)
        addr = addr.strip("[]")
        logging.info("Exporting metrics on %s", export_addr)
        start_http_server(port, addr=addr)

    def _init_metrics(self):
        """
        Initializes all metrics to 0. Subclasses should initialize their metrics here and
        must call the super method.
        """
        PKT_BUF_TOTAL.labels(**self._labels).set(0)
        PKT_BUF_BYTES.labels(**self._labels).set(0)
        PKTS_DROPPED_TOTAL.labels(**self._labels).inc(0)
        UNV_SEGS_TOTAL.labels(**self._labels).set(0)
        PENDING_TRC_REQS_TOTAL.labels(**self._labels).set(0)
        PENDING_CERT_REQS_TOTAL.labels(**self._labels).set(0)
        CONNECTED_TO_DISPATCHER.labels(**self._labels).set(0)

    def _get_path_via_sciond(self, isd_as, flush=False):
        flags = lib_sciond.PathRequestFlags(flush=flush)
        start = time.time()
        while time.time() - start < API_TOUT:
            try:
                path_entries = lib_sciond.get_paths(isd_as, flags=flags)
            except lib_sciond.SCIONDLibError as e:
                logging.error("Error during path lookup: %s" % e)
                continue
            if path_entries:
                return path_entries[0].path()
        logging.warning("Unable to get path to %s from SCIOND.", isd_as)
        return None
