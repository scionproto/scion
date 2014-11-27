"""
topology_parser.py

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

import logging
import xml.etree.ElementTree as ET
from lib.packet.host_addr import IPv4HostAddr, IPv6HostAddr, SCIONHostAddr
from collections import defaultdict


class ElementType(object):
    """
    Defines constants for the element types in the topology file.
    """
    BEACON_SERVER = 0
    CERTIFICATE_SERVER = 1
    PATH_SERVER = 2
    CONTENT_CACHE = 3
    BORDER_ROUTER = 4


class NeighborType(object):
    """
    Defines constants for the possible types of neighbor ADs.
    """
    PARENT = 0
    CHILD = 1
    PEER = 2
    ROUTING = 3  # Inter ISD Link


class Element(object):
    """
    Base class for elements specified in the topology file.
    """
    def __init__(self, addr=None):
        self.addr = addr


class ServerElement(Element):
    """
    Represents one of the core servers in SCION.
    """
    def __init__(self, addr=None, server_type=0):
        Element.__init__(self, addr)
        self.type = server_type


class InterfaceElement(Element):
    """
    Represents an interface between two ADs.
    """
    def __init__(self, addr=None, if_id=0, neighbor=0,
                 neighbor_type=0, to_addr=None, udp_port=0, to_udp_port=0):
        Element.__init__(self, addr)
        self.if_id = if_id
        self.neighbor = neighbor
        self.neighbor_type = neighbor_type
        self.to_addr = to_addr
        self.udp_port = udp_port
        self.to_udp_port = to_udp_port
        self.initialized = False


class RouterElement(Element):
    """
    Represents a router.
    """
    def __init__(self, addr=None, interface=None):
        Element.__init__(self, addr)
        self.interface = interface


class ClientElement(Element):
    """
    Represents a client.
    """
    def __init__(self, addr=None):
        Element.__init__(self, addr)


class Topology(object):
    """
    Handles parsing a SCION topology XML file.
    """
    def __init__(self, filename=None):
        self.ad_id = 0
        self.isd_id = 0
        self.is_core_ad = False
        self.routers = defaultdict(list)
        self.servers = {}
        self.gateways = {}
        self.clients = []
        self._filename = None
        self._topo = None
        if filename is not None:
            self.load_file(filename)

    def load_file(self, filename):
        """
        Loads an XML file and creates an element tree for further parsing.
        """
        assert isinstance(filename, str)
        self._filename = filename
        self._topo = ET.parse(filename)

    def parse(self):
        """
        Parses the topology file and populates
        """
        assert self._topo is not None, "Must load file first"
        topology = self._topo.getroot()
        is_core_ad = topology.find("Core")
        if is_core_ad is not None:
            self.is_core_ad = bool(int(is_core_ad.text))
        isd_id = topology.find("ISDID")
        if isd_id is not None:
            self.isd_id = int(isd_id.text)
        ad_id = topology.find("ADID")
        if ad_id is not None:
            self.ad_id = int(ad_id.text)
        self._parse_servers()
        self._parse_routers()
        self._parse_clients()

    def _parse_servers(self):
        """
        Parses the servers in the topology file.
        """
        servers = self._topo.getroot().find("Servers")
        if servers is None:
            logging.info("No servers found in %s", self._filename)
            return
        for server in servers:
            element = ServerElement()
            self._parse_address(server, element)
            if server.tag == "BeaconServer":
                element.type = ElementType.BEACON_SERVER
            elif server.tag == "CertificateServer":
                element.type = ElementType.CERTIFICATE_SERVER
            elif server.tag == "PathServer":
                element.type = ElementType.PATH_SERVER
            elif server.tag == "ContentCache":
                element.type = ElementType.CONTENT_CACHE
            else:
                logging.warning("Encountered unkown server tag '%s'",
                                server.tag)
                continue
            self.servers[element.type] = element

    def _parse_routers(self):
        """
        Parses the routers in the topology file.
        """
        routers = self._topo.getroot().find("BorderRouters")
        if routers is None:
            logging.info("No routers found in %s", self._filename)
            return
        for router in routers:
            element = RouterElement()
            self._parse_address(router, element)
            interfaces = router.findall("Interface")
            assert len(interfaces) <= 1, "Router can only have one interface"
            for interface in interfaces:
                self._parse_interface(interface, element)
            self.routers[element.interface.neighbor_type].append(element)

    def _parse_clients(self):
        """
        Parses the clients in the topology file.
        """
        clients = self._topo.getroot().find("Clients")
        if clients is None:
            logging.info("No clients found in %s", self._filename)
            return
        for client in clients:
            element = ClientElement()
            self.clients.append(element)

    def _parse_address(self, et_element, element):
        """
        Parses the address in an element.
        """
        assert ET.iselement(et_element)
        addr_type = et_element.find("AddrType").text
        addr = et_element.find("Addr").text
        to_addr = et_element.find("ToAddr")
        if addr_type.lower() == "ipv4":
            element.addr = IPv4HostAddr(addr)
            if to_addr is not None:
                element.to_addr = IPv4HostAddr(to_addr.text)
        elif addr_type.lower() == "ipv6":
            element.addr = IPv6HostAddr(addr)
            if to_addr is not None:
                element.to_addr = IPv6HostAddr(to_addr.text)
        elif addr_type.lower() == "scion":
            element.addr = SCIONHostAddr(int(addr))
            if to_addr is not None:
                element.to_addr = SCIONHostAddr(to_addr.text)

    def _parse_interface(self, et_element, router):
        """
        Parses an Interface element.
        """
        assert ET.iselement(et_element)
        if_el = InterfaceElement()
        if et_element.find("AddrType") is not None:
            self._parse_address(et_element, if_el)
        if_el.if_id = int(et_element.find("IFID").text)
        neighbor = et_element.find("NeighborAD")
        if neighbor is None:
            neighbor = et_element.find("NeighborISD")
        assert neighbor is not None
        if_el.neighbor = int(neighbor.text)
        neighbor_type = et_element.find("NeighborType").text
        if neighbor_type == "PARENT":
            if_el.neighbor_type = NeighborType.PARENT
        elif neighbor_type == "CHILD":
            if_el.neighbor_type = NeighborType.CHILD
        elif neighbor_type == "PEER":
            if_el.neighbor_type = NeighborType.PEER
        elif neighbor_type == "ROUTING":
            if_el.neighbor_type = NeighborType.ROUTING
        else:
            logging.warning("Encountered unknown neighbor type")
        if et_element.find("UdpPort") is not None:
            if_el.udp_port = int(et_element.find("UdpPort").text)
        if et_element.find("ToUdpPort") is not None:
            if_el.to_udp_port = int(et_element.find("ToUdpPort").text)
        router.interface = if_el
