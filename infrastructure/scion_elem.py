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

# SCION
from lib.config import Config
from lib.crypto.hash_tree import ConnectedHashTree
from lib.errors import SCIONParseError
from lib.defines import (
    AS_CONF_FILE,
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    PATH_SERVICE,
    SCION_UDP_EH_DATA_PORT,
    SERVICE_TYPES,
    SIBRA_SERVICE,
    STARTUP_QUIET_PERIOD,
    TCP_ACCEPT_POLLING_TOUT,
    TCP_TIMEOUT,
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
    MetadataBase,
    SCMPMetadata,
    SockOnlyMetadata,
    TCPMetadata,
    UDPMetadata,
)
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
from lib.util import hex_str


MAX_QUEUE = 30


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

    def __init__(self, server_id, conf_dir, host_addr=None, port=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param `HostAddrBase` host_addr:
            the interface to bind to. Overrides the address in the topology
            config.
        :param int port:
            the port to bind to. Overrides the address in the topology config.
        """
        self.id = server_id
        self.conf_dir = conf_dir
        self.ifid2br = {}
        self._port = port
        self.topology = Topology.from_file(
            os.path.join(self.conf_dir, TOPO_FILE))
        self.config = Config.from_file(
            os.path.join(self.conf_dir, AS_CONF_FILE))
        # Must be over-ridden by child classes:
        self.CTRL_PLD_CLASS_MAP = {}
        self.SCMP_PLD_CLASS_MAP = {}
        if self.SERVICE_TYPE:
            own_config = self.topology.get_own_config(self.SERVICE_TYPE,
                                                      server_id)
            if host_addr is None:
                host_addr = own_config.addr
            if self._port is None:
                self._port = own_config.port
        self.addr = SCIONAddr.from_values(self.topology.isd_as, host_addr)
        self.init_ifid2br()
        self.trust_store = TrustStore(self.conf_dir)
        self.total_dropped = 0
        self._core_ases = defaultdict(list)  # Mapping ISD_ID->list of core ASes
        self.init_core_ases()
        self.run_flag = threading.Event()
        self.run_flag.set()
        self.stopped_flag = threading.Event()
        self.stopped_flag.clear()
        self._in_buf = queue.Queue(MAX_QUEUE)
        self._socks = SocketMgr()
        self._setup_sockets(True)
        self._startup = time.time()
        if self.USE_TCP:
            self.DefaultMeta = TCPMetadata
        else:
            self.DefaultMeta = UDPMetadata

    def _setup_sockets(self, init):
        """
        Setup incoming socket and register with dispatcher
        """
        self._tcp_sock = None
        self._tcp_conns = queue.Queue(MAX_QUEUE)  # For active TCP connections.
        if self._port is None:
            # No scion socket desired.
            return
        svc = SERVICE_TO_SVC_A.get(self.SERVICE_TYPE)
        # Setup TCP "accept" socket.
        self._setup_tcp_accept_socket(svc)
        # Setup UDP socket
        self._udp_sock = ReliableSocket(
            reg=(self.addr, self._port, init, svc))
        if not self._udp_sock.registered:
            self._udp_sock = None
            return
        self._port = self._udp_sock.port
        self._socks.add(self._udp_sock, self.handle_recv)

    def _setup_tcp_accept_socket(self, svc):
        if not self.USE_TCP:
            return
        MAX_TRIES = 20
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
        for br in self.topology.get_all_border_routers():
            self.ifid2br[br.interface.if_id] = br

    def init_core_ases(self):
        """
        Initializes dict of core ASes.
        """
        for trc in self.trust_store.get_trcs():
            self._core_ases[trc.isd] = trc.get_core_ases()

    def is_core_as(self, isd_as):
        return isd_as in self._core_ases[isd_as[0]]

    def handle_msg_meta(self, msg, meta):
        """
        Main routine to handle incoming SCION messages.
        """
        logging.debug("handle_msg_meta() started: %s %s" % (msg, meta))

        if isinstance(meta, SCMPMetadata):
            handler = self._get_scmp_handler(meta.pkt)
        else:
            handler = self._get_ctrl_handler(msg)
        if not handler:
            logging.error("handler not found: %s", msg)
            return
        try:
            logging.debug("Calling handler, meta:%s", meta)
            # SIBRA operates on parsed packets.
            if (isinstance(meta, UDPMetadata) and
                    msg.PAYLOAD_CLASS == PayloadClass.SIBRA):
                handler(meta.pkt)
            else:
                handler(msg, meta)
        except SCIONBaseError:
            log_exception("Error handling message:\n%s" % msg)

    def _get_handler(self, pkt):
        # FIXME(PSz): needed only by python router.
        if pkt.l4_hdr.TYPE == L4Proto.UDP:
            return self._get_ctrl_handler(pkt.get_payload())
        elif pkt.l4_hdr.TYPE == L4Proto.SCMP:
            return self._get_scmp_handler(pkt)
        logging.error("L4 header type not supported: %s(%s)\n",
                      pkt.l4_hdr.TYPE, L4Proto.to_str(pkt.l4_hdr.TYPE))
        return None

    def _get_ctrl_handler(self, msg):
        try:
            type_map = self.CTRL_PLD_CLASS_MAP[msg.PAYLOAD_CLASS]
        except KeyError:
            logging.error("Control payload class not supported: %s\n%s",
                          msg.PAYLOAD_CLASS, msg)
            return None
        try:
            return type_map[msg.PAYLOAD_TYPE]
        except KeyError:
            logging.error("%s control payload type not supported: %s\n%s",
                          msg.PAYLOAD_CLASS, msg.PAYLOAD_TYPE, msg)
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
            logging.error("SCMP %s type not supported: %s(%s)\n%s",
                          scmp.type, scmp_type_name(scmp.type), pkt)
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
        assert isinstance(e, DROP)
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
        logging.warning("Reply:\n%s", reply)
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
            br = self.ifid2br[if_id]
            return br.addr, br.port
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
        cmn_hdr, addr_hdr = build_base_hdrs(self.addr, dst_addr)
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
        assert not isinstance(packet.addrs.src.host, HostAddrNone)
        assert not isinstance(packet.addrs.dst.host, HostAddrNone)
        assert isinstance(packet, SCIONBasePacket)
        assert isinstance(dst_port, int), dst_port
        if not self._udp_sock:
            return False
        return self._udp_sock.send(packet.pack(), (dst, dst_port))

    def send_meta(self, msg, meta, next_hop_port=None):
        assert isinstance(meta, MetadataBase)
        if isinstance(meta, TCPMetadata):
            assert not next_hop_port, next_hop_port
            return self._send_meta_tcp(msg, meta)
        elif isinstance(meta, SockOnlyMetadata):
            assert not next_hop_port, next_hop_port
            return meta.sock.send(msg)
        elif isinstance(meta, UDPMetadata):
            dst_port = meta.port
        else:
            logging.error("Unsupported metadata for:\n%s" % meta.__name__)
            return False

        pkt = self._build_packet(meta.host, meta.path, meta.ext_hdrs,
                                 meta.ia, msg, dst_port)
        if not next_hop_port:
            next_hop_port = self.get_first_hop(pkt)
        if not next_hop_port:
            logging.error("Can't find first hop, dropping packet\n%s", pkt)
            return False
        return self.send(pkt, *next_hop_port)

    def _send_meta_tcp(self, msg, meta):
        if not meta.sock:
            tcp_sock = self._tcp_sock_from_meta(meta)
            meta.sock = tcp_sock
            self._tcp_conns_put(tcp_sock)
        return meta.sock.send_msg(msg.pack_full())

    def _tcp_sock_from_meta(self, meta):
        assert meta.host
        if meta.ia is None:
            meta.ia = self.addr.isd_as
        if meta.path is None:
            meta.path = SCIONPath()
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
                self._tcp_conns.put(sock, block=False)
            except queue.Full:
                old_sock = self._tcp_conns.get_nowait()
                old_sock.close()
                logging.error("TCP: _tcp_conns is full. Closing an old socket.")
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
            except queue.Full:
                self._in_buf.get_nowait()
                dropped += 1
            else:
                break
        if dropped > 0:
            self.total_dropped += dropped
            logging.debug("%d packet(s) dropped (%d total dropped so far)",
                          dropped, self.total_dropped)

    def _get_msg_meta(self, packet, addr, sock):
        logging.debug("_get_msg_meta() called")
        pkt = self._parse_packet(packet)
        if not pkt:
            logging.error("Cannot parse packet:\n%s" % packet)
            return None, None
        # Create metadata:
        rev_pkt = pkt.reversed_copy()
        if rev_pkt.l4_hdr.TYPE == L4Proto.UDP:
            meta = UDPMetadata.from_values(ia=rev_pkt.addrs.dst.isd_as,
                                           host=rev_pkt.addrs.dst.host,
                                           path=rev_pkt.path,
                                           ext_hdrs=rev_pkt.ext_hdrs,
                                           port=rev_pkt.l4_hdr.dst_port)
        elif rev_pkt.l4_hdr.TYPE == L4Proto.SCMP:
            meta = SCMPMetadata.from_values(ia=rev_pkt.addrs.dst.isd_as,
                                            host=rev_pkt.addrs.dst.host,
                                            path=rev_pkt.path,
                                            ext_hdrs=rev_pkt.ext_hdrs)

        else:
            logging.error("Cannot create meta for: %s" % pkt)
            return None, None

        # FIXME(PSz): for now it is needed by SIBRA service.
        meta.pkt = pkt

        try:
            pkt.parse_payload()
        except SCIONParseError:
            logging.error("Cannot parse payload of: %s" % pkt)
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
            return
        self.packet_put(packet, addr, sock)

    def packet_recv(self):
        """
        Read packets from sockets, and put them into a :class:`queue.Queue`.
        """
        while self.run_flag.is_set():
            if not self._udp_sock:
                self._setup_sockets(False)
            for sock, callback in self._socks.select_(timeout=1.0):
                callback(sock)
        self._socks.close()
        self.stopped_flag.set()

    def _packet_process(self):
        """
        Read packets from a :class:`queue.Queue`, and process them.
        """
        while self.run_flag.is_set():
            try:
                self.handle_msg_meta(*self._in_buf.get(timeout=1.0))
            except queue.Empty:
                continue

    def _tcp_start(self):
        # FIXME(PSz): hack to get python router working.
        if not hasattr(self, "_tcp_sock") or not self.USE_TCP:
            return
        threading.Thread(
            target=thread_safety_net, args=(self._tcp_recv_loop,),
            name="Elem._tcp_recv_loop", daemon=True).start()
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

    def _tcp_recv_loop(self):
        active_conns = {}
        while self.run_flag.is_set():
            if not active_conns:
                # Have nothing to do, so block until another connection comes in
                tcp_sock = self._tcp_conns.get()
                active_conns[tcp_sock] = time.time()
            logging.debug("TCP: queue size: %d", self._tcp_conns.qsize())
            while not self._tcp_conns.empty():
                try:
                    active_conns[self._tcp_conns.get_nowait()] = time.time()
                except queue.Empty:
                    pass
            # Handle active connections.
            to_remove = []
            for tcp_sock in active_conns:
                msg, meta = tcp_sock.get_msg_meta()
                if msg:
                    self._in_buf_put((msg, meta))
                    active_conns[tcp_sock] = time.time()
                idle = time.time() - active_conns[tcp_sock]
                if idle > TCP_TIMEOUT or not tcp_sock.active:
                    to_remove.append(tcp_sock)
                logging.debug("TCP: Active: %s", tcp_sock.active)
            # Remove inactive connections.
            for tcp_sock in to_remove:
                tcp_sock.close()
                del active_conns[tcp_sock]
        # Is not running anymore.
        for tcp_sock in active_conns:
            tcp_sock.close()

    def _tcp_clean(self):
        if not hasattr(self, "_tcp_sock") or not self._tcp_sock:
            return
        # Close all TCP sockets.
        while not self._tcp_conns.empty():
            try:
                tcp_sock = self._tcp_conns.get_nowait()
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
        results = [(srv.addr, srv.port) for srv in service_map[qname]]
        # FIXME(kormat): replace with new discovery service when that's ready.
        #  results = self._dns.query(qname, fallback, self._quiet_startup())
        if not results:
            # No results from local toplogy either
            raise SCIONServiceLookupError("No %s servers found" % qname)
        return results

    def verify_asm(self, asm, rev_info):
        # FIXME(siva): We are removing the PCB only if any of up/downstream
        # interfaces are down, and not peer interfaces. If you do it for
        # peer interfaces too, you will end up removing some PCBs which are
        # still valid but contain that peer interface. So we need to add an
        # extension to the PCBMarking to identify which peer interfaces are
        # down
        hof = asm.pcbm(0).hof()
        root_verify = ConnectedHashTree.verify(rev_info, asm.p.hashTreeRoot)
        return ((rev_info.p.ifID in [hof.ingress_if, hof.egress_if]) and
                root_verify)
