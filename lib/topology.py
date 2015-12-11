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
:mod:`topology` --- SCION topology parser
===========================================
"""
# Stdlib
import logging

# SCION
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    DNS_SERVICE,
    PATH_SERVICE,
    ROUTER_SERVICE,
)
from lib.errors import SCIONKeyError
from lib.packet.host_addr import haddr_parse_interface
from lib.util import load_yaml_file


class Element(object):
    """
    The Element class is the base class for elements specified in the topology
    file.

    :ivar HostAddrBase addr: Host address of a server or edge router.
    :ivar str name: element name or id
    """

    def __init__(self, addr=None, name=None):
        """
        :param str addr: (addr_type, address) of the element's Host address.
        :param str name: element name or id
        """
        self.addr = None
        if addr:
            self.addr = haddr_parse_interface(addr)
        self.name = None
        if name is not None:
            self.name = str(name)


class ServerElement(Element):
    """
    The ServerElement class represents one of the servers in the AD.
    """

    def __init__(self, server_dict, name=None):
        """
        Initialize an instance of the class ServerElement.

        :param server_dict: contains information about a particular server.
        :type server_dict: dict
        :param name: server element name or id
        :type name: str
        """
        super().__init__(server_dict['Addr'], name)


class InterfaceElement(Element):
    """
    The InterfaceElement class represents one of the interfaces of an edge
    router.

    :ivar int if_id: the interface ID.
    :ivar int neighbor_ad: the AD identifier of the neighbor AD.
    :ivar int neighbor_isd: the ISD identifier of the neighbor AD.
    :ivar str neighbor_type:
        the type of the neighbor relative to the AD to which the interface
        belongs.
    :ivar int to_udp_port:
        the port number receiving UDP traffic on the other end of the interface.
    :ivar int udp_port: the port number used to send UDP traffic.
    """

    def __init__(self, interface_dict, name=None):
        """
        Initialize an instance of the class InterfaceElement.

        :param interface_dict: contains information about the interface.
        :type interface_dict: dict
        """
        super().__init__(interface_dict['Addr'], name)
        self.if_id = interface_dict['IFID']
        self.neighbor_ad = interface_dict['NeighborAD']
        self.neighbor_isd = interface_dict['NeighborISD']
        self.neighbor_type = interface_dict['NeighborType']
        self.to_udp_port = interface_dict['ToUdpPort']
        self.udp_port = interface_dict['UdpPort']
        self.bandwidth = interface_dict['Bandwidth']
        to_addr = interface_dict['ToAddr']
        self.to_addr = None
        if to_addr:
            self.to_addr = haddr_parse_interface(to_addr)


class RouterElement(Element):
    """
    The RouterElement class represents one of the edge routers.

    :ivar interface: one of the interfaces of the edge router.
    :type interface: :class:`InterfaceElement`
    """

    def __init__(self, router_dict, name=None):
        """
        Initialize an instance of the class RouterElement.

        :param router_dict: contains information about an edge router.
        :type router_dict: dict
        :param name: router element name or id
        :type name: str
        """
        super().__init__(router_dict['Addr'], name)
        self.interface = InterfaceElement(router_dict['Interface'])

    def __lt__(self, other):  # pragma: no cover
        return self.interface.if_id < other.interface.if_id


class Topology(object):
    """
    The Topology class parses the topology file of an AD and stores such
    information for further use.

    :ivar is_core_ad: tells whether an AD is a core AD or not.
    :vartype is_core_ad: bool
    :ivar isd_id: the ISD identifier.
    :vartype isd_id: int
    :ivar ad_id: the AD identifier.
    :vartype ad_id: int
    :ivar dns_domain: the dns domain the dns servers should use.
    :vartype dns_domain: str
    :ivar beacon_servers: beacons servers in the AD.
    :vartype beacon_servers: list
    :ivar certificate_servers: certificate servers in the AD.
    :vartype certificate_servers: list
    :ivar dns_servers: dns servers in the AD.
    :vartype dns_servers: list
    :ivar path_servers: path servers in the AD.
    :vartype path_servers: list
    :ivar parent_edge_routers: edge routers linking the AD to its parents.
    :vartype parent_edge_routers: list
    :ivar child_edge_routers: edge routers linking the AD to its children.
    :vartype child_edge_routers: list
    :ivar peer_edge_routers: edge router linking the AD to its peers.
    :vartype peer_edge_routers: list
    :ivar routing_edge_routers: edge router linking the core AD to another core
                                AD.
    :vartype routing_edge_routers: list
    """

    def __init__(self):
        """
        Initialize an instance of the class Topology.
        """
        self.is_core_ad = False
        self.isd_id = 0
        self.ad_id = 0
        self.dns_domain = ""
        self.beacon_servers = []
        self.certificate_servers = []
        self.dns_servers = []
        self.path_servers = []
        self.parent_edge_routers = []
        self.child_edge_routers = []
        self.peer_edge_routers = []
        self.routing_edge_routers = []
        self.zookeepers = []

    @classmethod
    def from_file(cls, topology_file):
        """
        Create a Topology instance from the file.

        :param topology_file: path to the topology file
        :type topology_file: str

        :returns: the newly created Topology instance
        :rtype: :class: `Topology`
        """
        return cls.from_dict(load_yaml_file(topology_file))

    @classmethod
    def from_dict(cls, topology_dict):
        """
        Create a Topology instance from the dictionary.

        :param topology_dict: dictionary representation of a topology
        :type topology_dict: dict

        :returns: the newly created Topology instance
        :rtype: :class:`Topology`
        """
        topology = cls()
        topology.parse_dict(topology_dict)
        return topology

    def parse_dict(self, topology):
        """
        Parse a topology dictionary and populate the instance's attributes.

        :param topology: dictionary representation of a topology
        :type topology: dict
        """
        self.is_core_ad = topology['Core']
        self.isd_id = topology['ISDID']
        self.ad_id = topology['ADID']
        self.dns_domain = topology['DnsDomain']
        self._parse_srv_dicts(topology)
        self._parse_router_dicts(topology)
        self._parse_zk_dicts(topology)

    def _parse_srv_dicts(self, topology):
        for type_, list_ in (
            ("BeaconServers", self.beacon_servers),
            ("CertificateServers", self.certificate_servers),
            ("DNSServers", self.dns_servers),
            ("PathServers", self.path_servers),
        ):
            for k, v in topology[type_].items():
                list_.append(ServerElement(v, k))

    def _parse_router_dicts(self, topology):
        for k, v in topology['EdgeRouters'].items():
            router = RouterElement(v, k)
            ntype_map = {
                'PARENT': self.parent_edge_routers,
                'CHILD': self.child_edge_routers,
                'PEER': self.peer_edge_routers,
                'ROUTING': self.routing_edge_routers,
            }
            ntype_map[router.interface.neighbor_type].append(router)

    def _parse_zk_dicts(self, topology):
        for zk in topology['Zookeepers'].values():
            haddr = haddr_parse_interface(zk['Addr'])
            zk_host = "[%s]:%s" % (haddr, zk['Port'])
            self.zookeepers.append(zk_host)

    def get_all_edge_routers(self):
        """
        Return all edge routers associated to the AD.

        :returns: all edge routers associated to the AD.
        :rtype: list
        """
        all_edge_routers = []
        all_edge_routers.extend(self.parent_edge_routers)
        all_edge_routers.extend(self.child_edge_routers)
        all_edge_routers.extend(self.peer_edge_routers)
        all_edge_routers.extend(self.routing_edge_routers)
        return all_edge_routers

    def get_own_config(self, server_type, server_id):
        """


        :param server_type:
        :type server_type:
        :param server_id:
        :type server_id:
        """
        type_map = {
            BEACON_SERVICE: self.beacon_servers,
            CERTIFICATE_SERVICE: self.certificate_servers,
            DNS_SERVICE: self.dns_servers,
            PATH_SERVICE: self.path_servers,
            ROUTER_SERVICE: self.get_all_edge_routers(),
        }
        try:
            target = type_map[server_type]
        except KeyError:
            logging.critical("Unknown server type: \"%s\"", server_type)
            raise SCIONKeyError from None

        for i in target:
            if i.name == server_id:
                return i
        else:
            logging.critical("Could not find server %s", server_id)
            raise SCIONKeyError from None
