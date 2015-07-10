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

Module docstring here.

.. note::
    Fill in the docstring.

"""

# Stdlib
import logging
import select
import socket

# SCION
from lib.config import Config
from lib.defines import SCION_BUFLEN, SCION_UDP_PORT
from lib.packet.scion_addr import SCIONAddr
from lib.topology import Topology


class SCIONElement(object):
    """
    Base class for the different kind of servers the SCION infrastructure
    provides.

    :ivar topology: the topology of the AD as seen by the server.
    :type topology: :class:`Topology`
    :ivar config: the configuration of the AD in which the server is located.
    :type config: :class:`lib.config.Config`
    :ivar ifid2addr: a dictionary mapping interface identifiers to the
                     corresponding border router addresses in the server's AD.
    :type ifid2addr: dict
    :ivar addr: a `SCIONAddr` object representing the server address.
    :type addr: :class:`lib.packet.scion_addr.SCIONAddr`
    """

    def __init__(self, server_type, topo_file, config_file=None, server_id=None,
                 host_addr=None, is_sim=False):
        """
        Create a new ServerBase instance.

        :param server_type: a shorthand of the server type, e.g. "bs" for a
                            beacon server.
        :type server_type: str
        :param topo_file: the name of the topology file.
        :type topo_file: str
        :param config_file: the name of the configuration file.
        :type config_file: str
        :param server_id: the local id of the server, e.g. for bs1-10-3, the id
                          would be '3'. Used to look up config from topology
                          file.
        :type server_id: str
        :param host_addr: the interface to bind to. Only used if server_id isn't
                          specified.
        :type host_addr: :class:`ipaddress._BaseAddress`

        :returns: the newly-created ServerBase instance
        :rtype: ServerBase
        :param is_sim: running in simulator
        :type is_sim: bool
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
        if config_file:
            self.parse_config(config_file)
        self.construct_ifid2addr_map()
        if not is_sim:
            self._local_socket = socket.socket(socket.AF_INET,
                                               socket.SOCK_DGRAM)
            self._local_socket.setsockopt(socket.SOL_SOCKET,
                                          socket.SO_REUSEADDR, 1)
            self._local_socket.bind((str(self.addr.host_addr), SCION_UDP_PORT))
            self._sockets = [self._local_socket]
            logging.info("%s: bound %s:%u", self.id, self.addr.host_addr,
                         SCION_UDP_PORT)

    @property
    def addr(self):
        """
        The address of the server as a :class:`lib.packet.scion_addr.SCIONAddr`
        object.

        :returns:
        :type:
        """
        return self._addr

    @addr.setter
    def addr(self, addr):
        """
        Set the address of the server. Must be a
        :class:`lib.packet.scion_addr.SCIONAddr` object.

        :param addr: the new server address.
        :type addr: :class:`lib.packet.scion_addr.SCIONAddr`
        """
        self.set_addr(addr)

    def set_addr(self, addr):
        """
        Set the address of the server. Must be a lib.SCIONAddr object
        """
        if not (isinstance(addr, SCIONAddr) or addr is None):
            raise TypeError("Addr must be of type 'SCIONAddr'")
        else:
            self._addr = addr

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
        pass

    def get_first_hop(self, spkt):
        """
        Returns first hop addr of down-path or end-host addr.

        :param spkt:
        :type spkt:

        :returns:
        :rtype:
        """
        opaque_field = spkt.hdr.path.get_first_hop_of()
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
        self._local_socket.sendto(packet.pack(), (str(dst), dst_port))

    def run(self):
        """
        Main routine to receive packets and pass them to
        :func:`handle_request()`.
        """
        while True:
            recvlist, _, _ = select.select(self._sockets, [], [])
            for sock in recvlist:
                packet, addr = sock.recvfrom(SCION_BUFLEN)
                self.handle_request(packet, addr, sock == self._local_socket)

    def clean(self):
        """
        Close open sockets.
        """
        for s in self._sockets:
            s.close()
