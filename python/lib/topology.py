# Copyright 2014 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
from lib.errors import SCIONKeyError
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.scion_addr import ISD_AS
from lib.types import (
    LinkType,
    ServiceType
)
from lib.util import load_yaml_file


class Element(object):
    """
    The Element class is the base class for elements specified in the topology
    file.

    :ivar HostAddrBase addr: Host address of a server or border router.
    :ivar str name: element name or id
    """
    def __init__(self, addrs=None, name=None):
        """
        :param dict addrs:
            contains the public and bind addresses. Only one public/bind addresses pair
            is chosen from all the available addresses in the map.
        :param str name: element name or id
        """
        public, bind = self._get_pub_bind(addrs)
        self.public = self._parse_addrs(public)
        self.bind = self._parse_addrs(bind)
        self.name = None
        if name is not None:
            self.name = str(name)

    def _get_pub_bind(self, addrs):
        if addrs is None:
            return None, None
        pub_bind = addrs.get('IPv6')
        if pub_bind is not None:
            return pub_bind['Public'], pub_bind.get('Bind')
        pub_bind = addrs.get('IPv4')
        if pub_bind is not None:
            return pub_bind['Public'], pub_bind.get('Bind')
        return None, None

    def _parse_addrs(self, value):
        if not value:
            return None
        return (haddr_parse_interface(value['Addr']), value['L4Port'])


class ServerElement(Element):
    """The ServerElement class represents one of the servers in the AS."""
    def __init__(self, server_dict, name=None):  # pragma: no cover
        """
        :param dict server_dict: contains information about a particular server.
        :param str name: server element name or id
        """
        super().__init__(server_dict['Addrs'], name)


class RouterAddrElement(object):
    """
    The RouterAddrElement class is the base class for elements specified in the
    Border router topology section.

    :ivar HostAddrBase addr: Host address of a border router.
    :ivar str name: element name or id
    """
    def __init__(self, addrs=None, name=None):
        """
        :param dict public:
            ((addr_type, address), overlay_port) of the element's public address.
            (i.e. the address visible to other network elements).
        :param dict bind:
            (addr_type, address) of the element's bind address, if any
            (i.e. the address the element uses to identify itself to the local
            operating system, if it differs from the public address due to NAT).
        :param str name: element name or id
        """
        public, bind = self._get_pub_bind(addrs)
        self.public = self._parse_addrs(public)
        self.bind = self._parse_addrs(bind)
        self.name = None
        if name is not None:
            self.name = str(name)

    def _get_pub_bind(self, addrs):
        if addrs is None:
            return None, None
        pub_bind = addrs.get('IPv6')
        if pub_bind is not None:
            return pub_bind['PublicOverlay'], pub_bind.get('BindOverlay')
        pub_bind = addrs.get('IPv4')
        if pub_bind is not None:
            return pub_bind['PublicOverlay'], pub_bind.get('BindOverlay')
        return None, None

    def _parse_addrs(self, value):
        if not value:
            return None
        return (haddr_parse_interface(value['Addr']), value['OverlayPort'])


class InterfaceElement(RouterAddrElement):
    """
    The InterfaceElement class represents one of the interfaces of a border
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
        :pacam int if_id: interface id
        :param dict interface_dict: contains information about the interface.
        """
        self.if_id = int(if_id)
        self.isd_as = ISD_AS(interface_dict['ISD_AS'])
        self.link_type = interface_dict['LinkTo'].lower()
        self.bandwidth = interface_dict['Bandwidth']
        self.mtu = interface_dict['MTU']
        self.overlay = interface_dict.get('Overlay')
        self.to_if_id = 0  # Filled in later by IFID packets
        self.remote = self._parse_addrs(interface_dict.get('RemoteOverlay'))
        super().__init__(self._new_addrs(interface_dict), name)

    def _new_addrs(self, interface_dict):
        addrs = {}
        if not self.overlay:
            return None
        if 'IPv4' in self.overlay:
            addrType = 'IPv4'
        else:  # Assume IPv6
            addrType = 'IPv6'
        addrs[addrType] = {}
        addrs[addrType]['PublicOverlay'] = interface_dict['PublicOverlay']
        bind = interface_dict.get('BindOverlay')
        if bind is not None:
            addrs[addrType]['BindOverlay'] = bind
        return addrs

    def __lt__(self, other):  # pragma: no cover
        return self.if_id < other.if_id


class RouterElement(object):
    """
    The RouterElement class represents one of the border routers.
    """
    def __init__(self, router_dict, name=None):  # pragma: no cover
        """
        :param dict router_dict: contains information about an border router.
        :param str name: router element name or id
        """
        self.name = name
        self.ctrl_addrs = Element(router_dict['CtrlAddr'])
        self.int_addrs = RouterAddrElement(router_dict['InternalAddrs'])
        self.interfaces = {}
        for if_id, intf in router_dict['Interfaces'].items():
            if_id = int(if_id)
            self.interfaces[if_id] = InterfaceElement(if_id, intf)

    def __lt__(self, other):  # pragma: no cover
        return self.name < other.name


class Topology(object):
    """
    The Topology class parses the topology file of an AS and stores such
    information for further use.

    :ivar bool is_core_as: tells whether an AS is a core AS or not.
    :ivar ISD_AS isd_is: the ISD-AS identifier.
    :ivar list beacon_servers: beacons servers in the AS.
    :ivar list certificate_servers: certificate servers in the AS.
    :ivar list path_servers: path servers in the AS.
    :ivar list discovery_servers: discovery servers in the AS.
    :ivar list border_routers: border routers in the AS.
    :ivar list parent_interfaces: BR interfaces linking to upstream ASes.
    :ivar list child_interfaces: BR interfaces linking to downstream ASes.
    :ivar list peer_interfaces: BR interfaces linking to peer ASes.
    :ivar list core_interfaces: BR interfaces linking to core ASes.
    :ivar list zookeepers: zookeeper instances in the AS.
    """
    def __init__(self):  # pragma: no cover
        self.is_core_as = False
        self.isd_as = None
        self.mtu = None
        self.beacon_servers = []
        self.certificate_servers = []
        self.path_servers = []
        self.sibra_servers = []
        self.discovery_servers = []
        self.border_routers = []
        self.parent_interfaces = []
        self.child_interfaces = []
        self.peer_interfaces = []
        self.core_interfaces = []
        self.zookeepers = []

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
        self.overlay = topology['Overlay']
        self._parse_srv_dicts(topology)
        self._parse_router_dicts(topology)
        self._parse_zk_dicts(topology)

    def _parse_srv_dicts(self, topology):
        for type_, list_ in (
            ("BeaconService", self.beacon_servers),
            ("CertificateService", self.certificate_servers),
            ("PathService", self.path_servers),
            ("SibraService", self.sibra_servers),
            ("DiscoveryService", self.discovery_servers),
        ):
            for k, v in topology.get(type_, {}).items():
                list_.append(ServerElement(v, k))

    def _parse_router_dicts(self, topology):
        for k, v in topology.get('BorderRouters', {}).items():
            router = RouterElement(v, k)
            self.border_routers.append(router)
            for intf in router.interfaces.values():
                ntype_map = {
                    LinkType.PARENT: self.parent_interfaces,
                    LinkType.CHILD: self.child_interfaces,
                    LinkType.PEER: self.peer_interfaces,
                    LinkType.CORE: self.core_interfaces,
                }
                ntype_map[intf.link_type].append(intf)

    def _parse_zk_dicts(self, topology):
        for zk in topology.get('ZookeeperService', {}).values():
            haddr = haddr_parse_interface(zk['Addr'])
            zk_host = "[%s]:%s" % (haddr, zk['L4Port'])
            self.zookeepers.append(zk_host)

    def get_all_interfaces(self):
        """
        Return all border router interfaces associated to the AS.

        :returns: all border router interfaces associated to the AS.
        :rtype: list
        """
        all_interfaces = []
        all_interfaces.extend(self.parent_interfaces)
        all_interfaces.extend(self.child_interfaces)
        all_interfaces.extend(self.peer_interfaces)
        all_interfaces.extend(self.core_interfaces)
        return all_interfaces

    def get_own_config(self, server_type, server_id):
        type_map = {
            ServiceType.BS: self.beacon_servers,
            ServiceType.CS: self.certificate_servers,
            ServiceType.PS: self.path_servers,
            ServiceType.SIBRA: self.sibra_servers,
            ServiceType.DS: self.discovery_servers,
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
