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
    PATH_SERVICE,
    ROUTER_SERVICE,
    SIBRA_SERVICE,
    SCIOND_SERVICE)
from lib.errors import SCIONKeyError
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.scion_addr import ISD_AS
from lib.types import LinkType
from lib.util import load_yaml_file


class Element(object):
    """
    The Element class is the base class for elements specified in the topology
    file.

    :ivar HostAddrBase addr: Host address of a server or border router.
    :ivar str name: element name or id
    """
    def __init__(self, addr=None, port=None, name=None):
        """
        :param str addr: (addr_type, address) of the element's Host address.
        :param str name: element name or id
        """
        self.addr = None
        if addr:
            self.addr = haddr_parse_interface(addr)
        self.port = port
        self.name = None
        if name is not None:
            self.name = str(name)


class ServerElement(Element):
    """The ServerElement class represents one of the servers in the AS."""
    def __init__(self, server_dict, name=None):  # pragma: no cover
        """
        :param dict server_dict: contains information about a particular server.
        :param str name: server element name or id
        """
        super().__init__(server_dict['Addr'], server_dict.get('Port'), name)


class InterfaceElement(Element):
    """
    The InterfaceElement class represents one of the interfaces of an border
    router.

    :ivar int if_id: the interface ID.
    :ivar int isd_as: the ISD-AS identifier of the neighbor AS.
    :ivar str link_type: the type of relationship to the neighbor AS.
    :ivar int to_udp_port:
        the port number receiving UDP traffic on the other end of the link.
    :ivar int udp_port: the port number used to send UDP traffic.
    """
    def __init__(self, interface_dict, name=None):
        """
        :param dict interface_dict: contains information about the interface.
        """
        super().__init__(interface_dict['Addr'], name)
        self.if_id = interface_dict['IFID']
        self.isd_as = ISD_AS(interface_dict['ISD_AS'])
        self.link_type = interface_dict['LinkType']
        self.to_udp_port = interface_dict['ToUdpPort']
        self.udp_port = interface_dict['UdpPort']
        self.bandwidth = interface_dict['Bandwidth']
        self.mtu = interface_dict['MTU']
        to_addr = interface_dict['ToAddr']
        self.to_addr = None
        if to_addr:
            self.to_addr = haddr_parse_interface(to_addr)
        self.to_if_id = 0  # Filled in later by IFID packets


class RouterElement(Element):
    """
    The RouterElement class represents one of the border routers.
    """
    def __init__(self, router_dict, name=None):  # pragma: no cover
        """
        :param dict router_dict: contains information about an border router.
        :param str name: router element name or id
        """
        super().__init__(router_dict['Addr'], router_dict['Port'], name)
        self.interface = InterfaceElement(router_dict['Interface'])

    def __lt__(self, other):  # pragma: no cover
        return self.interface.if_id < other.interface.if_id


class Topology(object):
    """
    The Topology class parses the topology file of an AS and stores such
    information for further use.

    :ivar bool is_core_as: tells whether an AS is a core AS or not.
    :ivar ISD_AS isd_is: the ISD-AS identifier.
    :ivar list beacon_servers: beacons servers in the AS.
    :ivar list certificate_servers: certificate servers in the AS.
    :ivar list path_servers: path servers in the AS.
    :ivar list parent_border_routers:
        border routers linking the AS to its parents.
    :ivar list child_border_routers:
        border routers linking the AS to its children.
    :ivar list peer_border_routers: border router linking the AS to its peers.
    :ivar list core_border_routers:
        border router linking the core AS to another core AS.
    """
    def __init__(self):  # pragma: no cover
        self.is_core_as = False
        self.isd_as = None
        self.mtu = None
        self.beacon_servers = []
        self.certificate_servers = []
        self.path_servers = []
        self.sibra_servers = []
        self.parent_border_routers = []
        self.child_border_routers = []
        self.peer_border_routers = []
        self.core_border_routers = []
        self.zookeepers = []
        self.scionds = []

    @classmethod
    def from_file(cls, topology_file):  # pragma: no cover
        """
        Create a Topology instance from the file.

        :param str topology_file: path to the topology file
        """
        return cls.from_dict(load_yaml_file(topology_file))

    @classmethod
    def from_dict(cls, topology_dict):  # pragma: no cover
        """
        Create a Topology instance from the dictionary.

        :param dict topology_dict: dictionary representation of a topology
        :returns: the newly created Topology instance
        :rtype: :class:`Topology`
        """
        topology = cls()
        topology.parse_dict(topology_dict)
        return topology

    def parse_dict(self, topology):
        """
        Parse a topology dictionary and populate the instance's attributes.

        :param dict topology: dictionary representation of a topology
        """
        self.is_core_as = topology['Core']
        self.isd_as = ISD_AS(topology['ISD_AS'])
        self.mtu = topology['MTU']
        self._parse_srv_dicts(topology)
        self._parse_router_dicts(topology)
        self._parse_zk_dicts(topology)

    def _parse_srv_dicts(self, topology):
        for type_, list_ in (
            ("BeaconServers", self.beacon_servers),
            ("CertificateServers", self.certificate_servers),
            ("PathServers", self.path_servers),
            ("SibraServers", self.sibra_servers),
            ("Sciond", self.scionds),
        ):
            for k, v in topology[type_].items():
                list_.append(ServerElement(v, k))

    def _parse_router_dicts(self, topology):
        for k, v in topology['BorderRouters'].items():
            router = RouterElement(v, k)
            ntype_map = {
                LinkType.PARENT: self.parent_border_routers,
                LinkType.CHILD: self.child_border_routers,
                LinkType.PEER: self.peer_border_routers,
                LinkType.CORE: self.core_border_routers,
            }
            ntype_map[router.interface.link_type].append(router)

    def _parse_zk_dicts(self, topology):
        for zk in topology['Zookeepers'].values():
            haddr = haddr_parse_interface(zk['Addr'])
            zk_host = "[%s]:%s" % (haddr, zk['Port'])
            self.zookeepers.append(zk_host)

    def get_all_border_routers(self):
        """
        Return all border routers associated to the AS.

        :returns: all border routers associated to the AS.
        :rtype: list
        """
        all_border_routers = []
        all_border_routers.extend(self.parent_border_routers)
        all_border_routers.extend(self.child_border_routers)
        all_border_routers.extend(self.peer_border_routers)
        all_border_routers.extend(self.core_border_routers)
        return all_border_routers

    def get_own_config(self, server_type, server_id):
        type_map = {
            BEACON_SERVICE: self.beacon_servers,
            CERTIFICATE_SERVICE: self.certificate_servers,
            PATH_SERVICE: self.path_servers,
            ROUTER_SERVICE: self.get_all_border_routers(),
            SIBRA_SERVICE: self.sibra_servers,
            SCIOND_SERVICE: self.scionds,
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
            logging.critical("Could not find server: %s", server_id)
            raise SCIONKeyError from None

    def get_sciond_config(self, server_id):
        for i in self.scionds:
            if i.name == server_id:
                return i
        else:
            logging.critical("Could not find Sciond to server: %s", server_id)
            raise SCIONKeyError from None
