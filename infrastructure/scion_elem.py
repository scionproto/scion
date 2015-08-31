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
import queue
import threading
from abc import ABCMeta, abstractmethod

# SCION
from lib.config import Config
from lib.defines import (
    BEACON_SERVICE,
    DNS_SERVICE,
    CERTIFICATE_SERVICE,
    PATH_SERVICE,
    SERVICE_TYPES,
)
from lib.defines import SCION_UDP_PORT
from lib.dnsclient import DNSCachingClient
from lib.errors import SCIONServiceLookupError
from lib.packet.scion_addr import SCIONAddr
from lib.socket import UDPSocket, UDPSocketMgr
from lib.thread import thread_safety_net
from lib.topology import Topology


class SCIONElement(object, metaclass=ABCMeta):
    """
    Base class for the different kind of servers the SCION infrastructure
    provides.

    :ivar `Topology` topology: the topology of the AD as seen by the server.
    :ivar `Config` config:
        the configuration of the AD in which the server is located.
    :ivar dict ifid2addr:
        a dictionary mapping interface identifiers to the corresponding border
        router addresses in the server's AD.
    :ivar `SCIONAddr` addr: the server's address.
    """

    def __init__(self, server_type, topo_file, config_file=None, server_id=None,
                 host_addr=None, is_sim=False):
        """
        :param str server_type:
            a service type from :const:`lib.defines.SERVICE_TYPES`. E.g.
            ``"bs"``.
        :param str topo_file: path name of the topology file.
        :param str config_file: path name of the configuration file.
        :param str server_id:
            the local id of the server. E.g. for `bs1-10-3`, the id would be
            ``"3"``. Used to look up config from topology file.
        :param `HostAddrBase` host_addr:
            the interface to bind to. Only used if `server_id` isn't specified.
        :param bool is_sim: running in simulator
        """
        self._addr = None
        self.topology = None
        self.config = None
        self.ifid2addr = {}
        self.parse_topology(topo_file)
        if server_id is not None:
            own_config = self.topology.get_own_config(server_type, server_id)
            self.id = "%s%s-%s-%s" % (server_type, self.topology.isd_id,
                                      self.topology.ad_id, own_config.name)
            host_addr = own_config.addr
        else:
            self.id = server_type
        self.addr = SCIONAddr.from_values(self.topology.isd_id,
                                          self.topology.ad_id, host_addr)
        self._dns = DNSCachingClient(
            [str(s.addr) for s in self.topology.dns_servers],
            self.topology.dns_domain)
        if config_file:
            self.parse_config(config_file)
        self.construct_ifid2addr_map()
        if not is_sim:
            self.run_flag = threading.Event()
            self.stopped_flag = threading.Event()
            self.stopped_flag.set()
            self._in_buf = queue.Queue()
            self._socks = UDPSocketMgr()
            self._local_sock = UDPSocket(
                bind=(str(self.addr.host_addr), SCION_UDP_PORT, self.id),
                addr_type=self.addr.host_addr.TYPE,
            )
            self._socks.add(self._local_sock)

    def parse_topology(self, topo_file):
        """
        Instantiate a Topology object given 'topo_file'.

        :param topo_file: the topology file name.
        :type topo_file: str
        """
        assert isinstance(topo_file, str)
        self.topology = Topology.from_file(topo_file)

    def parse_config(self, config_file):
        """
        Instantiate a Config object given 'config_file'.

        :param config_file: the configuration file name.
        :type config_file: str
        """
        assert isinstance(config_file, str)
        self.config = Config.from_file(config_file)

    def construct_ifid2addr_map(self):
        """
        Construct the mapping between the local interface IDs and the address
        of the neighbors connected to those interfaces.
        """
        assert self.topology is not None
        for edge_router in self.topology.get_all_edge_routers():
            self.ifid2addr[edge_router.interface.if_id] = edge_router.addr

    @abstractmethod
    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets. Subclasses have to
        override this to provide their functionality.

        :param packet:
        :type packet:
        :param sender:
        :type sender:
        :param from_local_socket:
        :type from_local_socket:
        """
        raise NotImplementedError

    def get_first_hop(self, spkt):
        """
        Returns first hop addr of down-path or end-host addr.

        :param spkt:
        :type spkt:

        :returns:
        :rtype:
        """
        opaque_field = spkt.hdr.get_path().get_first_hof()
        if opaque_field is None:  # EmptyPath
            return (spkt.hdr.dst_addr.host_addr, SCION_UDP_PORT)
        else:
            if spkt.hdr.is_on_up_path():
                return (self.ifid2addr[opaque_field.ingress_if], SCION_UDP_PORT)
            else:
                return (self.ifid2addr[opaque_field.egress_if], SCION_UDP_PORT)

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*) using the local socket.
        Calling ``packet.pack()`` should return :class:`bytes`, and
        ``dst.__str__()`` should return a string representing an IPv4 address.

        :param packet: the packet to be sent to the destination.
        :type packet:
        :param dst: the destination IPv4 address.
        :type dst: str
        :param dst_port: the destination port number.
        :type dst_port: int
        """
        self._local_sock.send(packet.pack(), (str(dst), dst_port))

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

        self._packet_process()

    def packet_recv(self):
        """
        Read packets from sockets, and put them into a :class:`queue.Queue`.
        """
        while self.run_flag.is_set():
            for sock in self._socks.select_(timeout=1.0):
                while True:
                    try:
                        # Read from socket until its buffer is empty.
                        packet, addr = sock.recv(block=False)
                        self._in_buf.put((packet, addr,
                                          sock == self._local_sock))
                    except BlockingIOError:
                        break
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
        self.stopped_flag.wait()
        self._socks.close()

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
        }
        # Generate fallback from local topology
        fallback = [srv.addr for srv in service_map[qname]]
        results = self._dns.query(qname, fallback)
        if not results:
            # No results from local toplogy either
            raise SCIONServiceLookupError("No %s servers found" % qname)
        return results
