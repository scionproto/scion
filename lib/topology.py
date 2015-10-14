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
from lib.packet.host_addr import haddr_parse
from lib.util import load_json_file


class Element(object):
    """
    The Element class is the base class for elements specified in the topology
    file.

    :ivar HostAddrBase addr: Host address of a server or edge router.
    :ivar str name: element name or id
    """

    def __init__(self, addr_info=(), name=None):
        """
        :param tuple addr: (addr_type, address) of the element's Host address.
        :param str name: element name or id
        """
        self.addr = None
        if addr_info:
            self.addr = haddr_parse(*addr_info)
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
        super().__init__((server_dict['AddrType'], server_dict['Addr']), name)


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
        super().__init__((interface_dict['AddrType'], interface_dict['Addr']),
                         name)
        self.if_id = interface_dict['IFID']
        self.neighbor_ad = interface_dict['NeighborAD']
        self.neighbor_isd = interface_dict['NeighborISD']
        self.neighbor_type = interface_dict['NeighborType']
        self.to_udp_port = interface_dict['ToUdpPort']
        self.udp_port = interface_dict['UdpPort']
        to_addr = interface_dict['ToAddr']
        if to_addr is None:
            self.to_addr = None
        else:
            self.to_addr = haddr_parse(interface_dict['AddrType'], to_addr)


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
        super().__init__((router_dict['AddrType'], router_dict['Addr']), name)
        self.interface = InterfaceElement(router_dict['Interface'])


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
        return cls.from_dict(load_json_file(topology_file))

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
        self.is_core_ad = (topology['Core'] == 1)
        self.isd_id = topology['ISDID']
        self.ad_id = topology['ADID']
        self.dns_domain = topology['DnsDomain']
        for bs_key in topology['BeaconServers']:
            b_server = ServerElement(topology['BeaconServers'][bs_key],
                                     bs_key)
            self.beacon_servers.append(b_server)
        for cs_key in topology['CertificateServers']:
            c_server = ServerElement(topology['CertificateServers'][cs_key],
                                     cs_key)
            self.certificate_servers.append(c_server)
        for ds_key in topology['DNSServers']:
            d_server = ServerElement(topology['DNSServers'][ds_key],
                                     ds_key)
            self.dns_servers.append(d_server)
        for ps_key in topology['PathServers']:
            p_server = ServerElement(topology['PathServers'][ps_key],
                                     ps_key)
            self.path_servers.append(p_server)
        for er_key in topology['EdgeRouters']:
            edge_router = RouterElement(topology['EdgeRouters'][er_key],
                                        er_key)
            if edge_router.interface.neighbor_type == 'PARENT':
                self.parent_edge_routers.append(edge_router)
            elif edge_router.interface.neighbor_type == 'CHILD':
                self.child_edge_routers.append(edge_router)
            elif edge_router.interface.neighbor_type == 'PEER':
                self.peer_edge_routers.append(edge_router)
            elif edge_router.interface.neighbor_type == 'ROUTING':
                self.routing_edge_routers.append(edge_router)
            else:
                logging.warning("Encountered unknown neighbor type")
        for zk in topology['Zookeepers'].values():
            if zk['AddrType'] == "IPV4":
                zk_host = "%s:%s" % (zk['Addr'], zk['ClientPort'])
            elif zk['AddrType'] == "IPV6":
                zk_host = "[%s]:%s" % (zk['Addr'], zk['ClientPort'])
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
        target = None
        if server_type == BEACON_SERVICE:
            target = self.beacon_servers
        elif server_type == CERTIFICATE_SERVICE:
            target = self.certificate_servers
        elif server_type == DNS_SERVICE:
            target = self.dns_servers
        elif server_type == PATH_SERVICE:
            target = self.path_servers
        elif server_type == ROUTER_SERVICE:
            target = self.get_all_edge_routers()
        else:
            logging.error("Unknown server type: \"%s\"", server_type)
            return

        for i in target:
            if i.name == server_id:
                return i
        else:
            logging.error("Could not find server %s%s-%s-%s", server_type,
                          self.isd_id, self.ad_id, server_id)
