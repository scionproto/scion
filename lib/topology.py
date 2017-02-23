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
)
from lib.errors import SCIONKeyError
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.scion_addr import ISD_AS
from lib.types import LinkType
from lib.util import (
    load_yaml_file,
    load_json_file,
)


class Element(object):
    """
    The Element class is the base class for elements specified in the topology
    file.

    :ivar HostAddrBase addr: Host address of a server or border router.
    :ivar str name: element name or id
    """
    def __init__(self, public=None, bind=None, name=None):
        """
        :param str addr: (addr_type, address) of the element's Host address.
        :param str name: element name or id
        """
        self.public = []
        self.bind = []
        if public:
            for attr in public:
                self.public.append({haddr_parse_interface(attr['Addr']), attr['L4Port']})
        if bind:
            for attr in bind:
                if attr:
                    self.bind.append({haddr_parse_interface(attr['Addr']), attr['L4Port']})
                else:
                    self.bind.append({})
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
        public = []
        bind = []
        for attr in server_dict['Public']:
            public.append(attr)
            if 'Bind' in server_dict:
                bind.append(attr)
            else:
                bind.append({})
        super().__init__(public, bind, name)


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
    def __init__(self, if_id, interface_dict, name=None):
        """
        :param str if_id: contains information about the interface identification number
        :param dict interface_dict: contains information about the interface.
        """
        self.if_id = if_id
        public = []
        bind = []
        public.append(interface_dict['Public'])
        if 'Bind' in interface_dict:
            bind.append(interface_dict['Bind'])
        self.isd_as = ISD_AS(interface_dict['ISD_AS'])
        self.link_type = interface_dict['LinkType']
        self.to_udp_port = interface_dict['Remote']['L4Port']
        self.bandwidth = interface_dict['Bandwidth']
        self.mtu = interface_dict['MTU']
        to_addr = interface_dict['Remote']['Addr']
        if to_addr:
            self.to_addr = haddr_parse_interface(to_addr)
        self.to_if_id =0 # Filled in later by IFID packets
        super().__init__(public, bind, name)


class InternalAddrElement(Element):
    """
    The InternalAddrElement class represents one of the internal address of 
    border router.

    """
    def __init__(self, internaladdr_dict, name=None):
        """
        :param dict internaladdr_dict: contains information about the internal address
        """
        public = []
        bind = []
        for attr in internaladdr_dict:
            if "Public" in attr:
                for addr in internaladdr_dict[attr]:
                    public.append(addr)
            else:
                for addr in internaladdr_dict[attr]:
                    bind.append(addr)
        super().__init__(public, bind, name)

class RouterElement(object):
    """
    The RouterElement class represents one of the border routers.
    """
    def __init__(self, router_dict, name=None):  # pragma: no cover
        """
        :param dict router_dict: contains information about an border router.
        :param str name: router element name or id
        """
        self.internaladdrs = []
        for attr in router_dict['InternalAddrs']:
            self.internaladdrs.append(InternalAddrElement(attr))
        self.interface = []
        for attr in router_dict['Interfaces']:
            self.interface.append(InterfaceElement(attr, router_dict['Interfaces'][attr]))

    def __lt__(self, other):  # pragma: no cover
        # TODO(jonghoonkwon): TBD to modify this function
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

    @classmethod
    def from_file(cls, topology_file):  # pragma: no cover
        """
        Create a Topology instance from the file.

        :param str topology_file: path to the topology file
        """
        if topology_file.endswith('.yml'):
            return cls.from_dict(load_yaml_file(topology_file))
        elif topology_file.endswith('.json'):
            return cls.from_dict(load_json_file(topology_file))

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
            ("BeaconService", self.beacon_servers),
            ("CertificateService", self.certificate_servers),
            ("PathService", self.path_servers),
            ("SibraService", self.sibra_servers),
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
            for interface in router.interface:
                ntype_map[interface.link_type].append(router)

    def _parse_zk_dicts(self, topology):
        for zk in topology['ZookeeperService'].values():
            haddr = haddr_parse_interface(zk['Addr'])
            zk_host = "[%s]:%s" % (haddr, zk['L4Port'])
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
