# Copyright 2014 ETH Zurich

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`server` --- Base class for SCION servers
==============================================

Module docstring here.

.. note::
    Fill in the docstring.

"""

from lib.packet.host_addr import HostAddr
from lib.topology import Topology
from lib.config import Config
from lib.crypto.trc import TRC
import logging
import socket
import select


SCION_UDP_PORT = 30040
SCION_UDP_EH_DATA_PORT = 30041
BUFLEN = 8092

class SCIONElement(object):
    """
    Base class for the different kind of servers the SCION infrastructure
    provides.

    :ivar topology: the topology of the AD as seen by the server.
    :vartype topology: :class:`Topology`
    :ivar config: the configuration of the AD in which the server is located.
    :vartype config: :class:`lib.config.Config`
    :ivar ifid2addr: a dictionary mapping interface identifiers to the
        corresponding border router addresses in the server's AD.
    :vartype ifid2addr: dict
    :ivar addr: a `HostAddr` object representing the server address.
    :vartype addr: :class:`lib.packet.host_addr.HostAddr`
    """

    def __init__(self, addr, topo_file, config_file=None, trc_file=None):
        """
        Create a new ServerBase instance.

        :param addr: the address of the server.
        :type addr: :class:`HostAddr`
        :param topo_file: the name of the topology file.
        :type topo_file: str
        :param config_file: the name of the configuration file.
        :type config_file: str

        :returns: the newly-created ServerBase instance
        :rtype: ServerBase
        """
        self._addr = None
        self.topology = None
        self.config = None
        self.trc = None
        self.ifid2addr = {}
        self.addr = addr
        self.parse_topology(topo_file)
        if config_file is not None:
            self.parse_config(config_file)
        if trc_file is not None:
            self.parse_trc(trc_file)
        self.construct_ifid2addr_map()
        self._local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._local_socket.bind((str(self.addr), SCION_UDP_PORT))
        self._sockets = [self._local_socket]
        logging.info("Bound %s:%u", self.addr, SCION_UDP_PORT)

    @property
    def addr(self):
        """
        The address of the server as a :class:`lib.packet.host_addr.HostAddr`
        object.
        """
        return self._addr

    @addr.setter
    def addr(self, addr):
        """
        Set the address of the server. Must be a
        :class:`lib.packet.host_addr.HostAddr` object.

        :param addr: the new server address.
        :type addr: :class:`lib.packet.host_addr.HostAddr`
        """
        self.set_addr(addr)

    def set_addr(self, addr):
        """
        Sets the address of the server. Must be a lib.HostAddr object
        """
        if not (isinstance(addr, HostAddr) or addr is None):
            raise TypeError("Addr must be of type 'HostAddr'")
        else:
            self._addr = addr

    def parse_topology(self, topo_file):
        """
        Instantiate a :class:`lib.topology.Topology` object and pases an AD
        topology from a file.

        :param topo_file: the topology file name.
        :type topo_file: str
        """
        assert isinstance(topo_file, str)
        self.topology = Topology(topo_file)

    def parse_config(self, config_file):
        """
        Instantiates a ConfigParser and parses the config given by
        *config_file*.

        :param config_file: the configuration file name.
        :type config_file: str
        """
        assert isinstance(config_file, str)
        self.config = Config(config_file)

    def parse_trc(self, trc_file):
        """
        Instantiates a TRCParser and parses the TRC given by 'rot_file'.
        """
        assert isinstance(trc_file, str)
        self.trc = TRC(trc_file)

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
        """
        pass

    def get_first_hop(self, spkt):
        """
        Returns first hop addr of down-path or end-host addr.
        """
        opaque_field = spkt.hdr.path.get_first_hop_of()
        if opaque_field is None:  # EmptyPath
            return (spkt.hdr.dst_addr, SCION_UDP_PORT)
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
                packet, addr = sock.recvfrom(BUFLEN)
                self.handle_request(packet, addr, sock == self._local_socket)

    def clean(self):
        """
        Close open sockets.
        """
        for s in self._sockets:
            s.close()
