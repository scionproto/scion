"""
server.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from lib.config import Config
from lib.packet.host_addr import HostAddr
from lib.topology import Topology
import socket
import select

#TODO do we need Define class or smth? 
SCION_UDP_PORT=30040
BUFLEN=8092

class ServerBase(object):
    """
    Base class for the different kind of servers the SCION infrastructure
    provides.
    """

    def __init__(self, addr, topo_file, config_file):
        self._addr = None
        self.topology = None
        self.config = None
        self.ifid2addr = {}

        self.addr = addr

        self.parse_topology(topo_file)
        self.parse_config(config_file)
        self.construct_ifid2addr_map()

        self._local_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._local_socket.bind((str(self.addr), SCION_UDP_PORT))
        self._sockets=[self._local_socket]
        print("binded", str(self.addr), SCION_UDP_PORT )

    @property
    def addr(self):
        """
        Returns the address of the server as a lib.HostAddr object
        """
        return self._addr

    @addr.setter
    def addr(self, addr):
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
        Instantiates a TopologyParser and parses the topology given by
        'topo_file'.
        """
        assert isinstance(topo_file, str)
        self.topology = Topology(topo_file)
        self.topology.parse()

    def parse_config(self, config_file):
        """
        Instantiates a ConfigParser and parses the config given by
        'config_file'.
        """
        assert isinstance(config_file, str)
        self.config = Config(config_file)
        self.config.parse()

    def construct_ifid2addr_map(self):
        """
        Constructs the mapping between the local ifid and the address of the
        neighbors.
        """
        assert self.topology is not None
        assert self.config is not None
        for router_list in self.topology.routers.values():
            for router in router_list:
                self.ifid2addr[router.interface.if_id] = router.addr

    def handle_request(self, packet, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets. Subclasses have to
        override this to provide their functionality.
        """
        pass

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Sends packet to dst (to port dst_port) using self._local_socket.
        """
        self._local_socket.sendto(packet,(str(dst),dst_port))

    def run(self):
        """
        Main routine to receive packets and pass them to handle_request().
        """
        while True:
             recvlist,_,_ = select.select( self._sockets, [], [])
             for sock in recvlist:
                 packet, addr = sock.recvfrom(BUFLEN)
                 self.handle_request(packet, sock==self._local_socket)
