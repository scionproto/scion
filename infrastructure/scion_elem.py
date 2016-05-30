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
from lib.defines import (
    AS_CONF_FILE,
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
    SCION_UDP_EH_DATA_PORT,
    SCION_UDP_PORT,
    SERVICE_TYPES,
    SIBRA_SERVICE,
    STARTUP_QUIET_PERIOD,
    TOPO_FILE,
)
from lib.dnsclient import DNSCachingClient
from lib.errors import (
    SCIONBaseError,
    SCIONChecksumFailed,
    SCIONServiceLookupError,
)
from lib.log import log_exception
from lib.packet.host_addr import HostAddrNone
from lib.packet.packet_base import PayloadRaw
from lib.packet.path import SCIONPath
from lib.packet.scion import (
    build_base_hdrs,
    SCIONBasePacket,
    SCIONL4Packet,
    SVCType
)
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
from lib.socket import ReliableSocket, SocketMgr
from lib.thread import thread_safety_net
from lib.trust_store import TrustStore
from lib.types import L4Proto, PayloadClass
from lib.topology import Topology
from lib.util import hex_str


MAX_QUEUE = 30
SVC_TYPE_MAP = {
    BEACON_SERVICE: SVCType.BS,
    CERTIFICATE_SERVICE: SVCType.CS,
    PATH_SERVICE: SVCType.PS,
    SIBRA_SERVICE: SVCType.SB
}


class SCIONElement(object):
    """
    Base class for the different kind of servers the SCION infrastructure
    provides.

    :ivar `Topology` topology: the topology of the AS as seen by the server.
    :ivar `Config` config:
        the configuration of the AS in which the server is located.
    :ivar dict ifid2addr:
        a dictionary mapping interface identifiers to the corresponding border
        router addresses in the server's AS.
    :ivar `SCIONAddr` addr: the server's address.
    """
    SERVICE_TYPE = None
    STARTUP_QUIET_PERIOD = STARTUP_QUIET_PERIOD

    def __init__(self, server_id, conf_dir, host_addr=None,
                 port=SCION_UDP_PORT):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param `HostAddrBase` host_addr:
            the interface to bind to. Overrides the address in the topology
            config.
        :param int port: the port to bind to.
        """
        self.id = server_id
        self.conf_dir = conf_dir
        self.ifid2addr = {}
        self._port = port
        self.topology = Topology.from_file(
            os.path.join(self.conf_dir, TOPO_FILE))
        self.config = Config.from_file(
            os.path.join(self.conf_dir, AS_CONF_FILE))
        # Must be over-ridden by child classes:
        self.CTRL_PLD_CLASS_MAP = {}
        self.SCMP_PLD_CLASS_MAP = {}
        if host_addr is None:
            own_config = self.topology.get_own_config(
                self.SERVICE_TYPE, server_id)
            host_addr = own_config.addr
        self.addr = SCIONAddr.from_values(self.topology.isd_as, host_addr)
        self._dns = DNSCachingClient(
            [str(s.addr) for s in self.topology.dns_servers],
            self.topology.dns_domain)
        self.construct_ifid2addr_map()
        self.trust_store = TrustStore(self.conf_dir)
        self.total_dropped = 0
        self._core_ases = defaultdict(list)  # Mapping ISD_ID->list of core ASes
        self.init_core_ases()
        self.run_flag = threading.Event()
        self.stopped_flag = threading.Event()
        self.stopped_flag.set()
        self._in_buf = queue.Queue(MAX_QUEUE)
        self._socks = SocketMgr()
        self._setup_socket(True)
        self._startup = time.time()

    def _setup_socket(self, init):
        """
        Setup incoming socket and register with dispatcher
        """
        svc = SVC_TYPE_MAP.get(self.SERVICE_TYPE)
        self._local_sock = ReliableSocket(
            reg=(self.addr, self._port, init, svc))
        if not self._local_sock.registered:
            self._local_sock = None
            return
        self._port = self._local_sock.port
        self._socks.add(self._local_sock, self.handle_recv)

    def construct_ifid2addr_map(self):
        """
        Construct the mapping between the local interface IDs and the address
        of the neighbors connected to those interfaces.
        """
        assert self.topology is not None
        for edge_router in self.topology.get_all_edge_routers():
            self.ifid2addr[edge_router.interface.if_id] = edge_router.addr

    def init_core_ases(self):
        """
        Initializes dict of core ASes.
        """
        for trc in self.trust_store.get_trcs():
            self._core_ases[trc.isd] = trc.get_core_ases()

    def is_core_as(self, isd_as):
        return isd_as in self._core_ases[isd_as[0]]

    def handle_request(self, packet, sender, from_local_socket=True, sock=None):
        """
        Main routine to handle incoming SCION packets. Subclasses may
        override this to provide their own functionality.
        """
        pkt = self._parse_packet(packet)
        if not pkt:
            return
        try:
            pkt.parse_payload()
        except SCIONBaseError:
            log_exception("Error parsing payload:\n%s" % pkt)
            return
        handler = self._get_handler(pkt)
        if not handler:
            return
        try:
            handler(pkt)
        except SCIONBaseError:
            log_exception("Error handling packet:\n%s" % pkt)

    def _get_handler(self, pkt):
        if pkt.l4_hdr.TYPE == L4Proto.UDP:
            return self._get_ctrl_handler(pkt)
        elif pkt.l4_hdr.TYPE == L4Proto.SCMP:
            return self._get_scmp_handler(pkt)
        logging.error("L4 header type not supported: %s(%s)\n",
                      pkt.l4_hdr.TYPE, L4Proto.to_str(pkt.l4_hdr.TYPE))
        return None

    def _get_ctrl_handler(self, pkt):
        pld = pkt.get_payload()
        try:
            type_map = self.CTRL_PLD_CLASS_MAP[pld.PAYLOAD_CLASS]
        except KeyError:
            logging.error("Control payload class not supported: %s\n%s",
                          PayloadClass.to_str(pld.PAYLOAD_CLASS), pkt)
            return None
        try:
            return type_map[pld.PAYLOAD_TYPE]
        except KeyError:
            logging.error("%s control payload type not supported: %s\n%s",
                          PayloadClass.to_str(pld.PAYLOAD_CLASS),
                          pld.PAYLOAD_TYPE, pkt)
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
        if_id = self._ext_first_hop(spkt)
        if if_id is None:
            if len(spkt.path) == 0:
                return self._empty_first_hop(spkt)
            if_id = spkt.path.get_fwd_if()
        if if_id in self.ifid2addr:
            return self.ifid2addr[if_id], SCION_UDP_EH_DATA_PORT
        logging.error("Unable to find first hop")
        return None, None

    def _ext_first_hop(self, spkt):
        for hdr in spkt.ext_hdrs:
            if_id = hdr.get_next_ifid()
            if if_id is not None:
                return if_id

    def _empty_first_hop(self, spkt):
        if spkt.addrs.src.isd_as != spkt.addrs.dst.isd_as:
            logging.error("Packet has no path but different src/dst ASes")
            logging.error(spkt)
            return None, None
        return spkt.addrs.dst.host, SCION_UDP_EH_DATA_PORT

    def _build_packet(self, dst_host=None, path=None, ext_hdrs=(),
                      dst_ia=None, payload=None, dst_port=SCION_UDP_PORT):
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

    def send(self, packet, dst, dst_port=SCION_UDP_EH_DATA_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*) using the local socket.
        Calling ``packet.pack()`` should return :class:`bytes`, and
        ``dst.__str__()`` should return a string representing an IPv4 address.

        :param packet: the packet to be sent to the destination.
        :param str dst: the destination IPv4 address.
        :param int dst_port: the destination port number.
        """
        assert not isinstance(packet.addrs.src.host, HostAddrNone)
        assert not isinstance(packet.addrs.dst.host, HostAddrNone)
        assert isinstance(packet, SCIONBasePacket)
        if not self._local_sock:
            return
        self._local_sock.send(packet.pack(), (dst, dst_port))

    def run(self):
        """
        Main routine to receive packets and pass them to
        :func:`handle_request()`.
        """
        self.stopped_flag.clear()
        self.run_flag.set()
        threading.Thread(
            target=thread_safety_net, args=(self.packet_recv,),
            name="Elem.packet_recv", daemon=True).start()
        try:
            self._packet_process()
        finally:
            self.stop()

    def packet_put(self, packet, addr, sock):
        """
        Try to put incoming packet in queue
        If queue is full, drop oldest packet in queue
        """
        from_local_as = sock == self._local_sock
        dropped = 0
        while True:
            try:
                self._in_buf.put((packet, addr, from_local_as, sock),
                                 block=False)
            except queue.Full:
                self._in_buf.get_nowait()
                dropped += 1
            else:
                break
        if dropped > 0:
            self.total_dropped += dropped
            logging.debug("%d packet(s) dropped (%d total dropped so far)",
                          dropped, self.total_dropped)

    def handle_accept(self, sock):
        """
        Callback to handle a ready listening socket
        """
        s = sock.accept()
        self._socks.add(s, self.handle_recv)

    def handle_recv(self, sock):
        """
        Callback to handle a ready recving socket
        """
        packet, addr = sock.recv()
        if packet is None:
            self._socks.remove(sock)
            sock.close()
            if sock == self._local_sock:
                self._local_sock = None
            return
        self.packet_put(packet, addr, sock)

    def packet_recv(self):
        """
        Read packets from sockets, and put them into a :class:`queue.Queue`.
        """
        while self.run_flag.is_set():
            if not self._local_sock:
                self._setup_socket(False)
            for sock, callback in self._socks.select_(timeout=1.0):
                callback(sock)
        self.stopped_flag.set()

    def _packet_process(self):
        """
        Read packets from a :class:`queue.Queue`, and process them.
        """
        while self.run_flag.is_set():
            try:
                self.handle_request(*self._in_buf.get(timeout=1.0))
            except queue.Empty:
                continue

    def stop(self):
        """
        Shut down the daemon thread
        """
        # Signal that the thread should stop
        self.run_flag.clear()
        # Wait for the thread to finish
        self.stopped_flag.wait(5)

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
            DNS_SERVICE: self.topology.dns_servers,
            PATH_SERVICE: self.topology.path_servers,
            SIBRA_SERVICE: self.topology.sibra_servers,
        }
        # Generate fallback from local topology
        fallback = [srv.addr for srv in service_map[qname]]
        results = self._dns.query(qname, fallback, self._quiet_startup())
        if not results:
            # No results from local toplogy either
            raise SCIONServiceLookupError("No %s servers found" % qname)
        return results
