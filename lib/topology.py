"""
topology.py

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

from collections import defaultdict
from enum import Enum, unique
import logging

from lib.packet.host_addr import *
import xml.etree.ElementTree as ET


class ElementType(object):
    """
    Defines constants to represent element types in the topology file.
    """
    BEACON_SERVER = 0
    CERTIFICATE_SERVER = 1
    PATH_SERVER = 2
    CONTENT_CACHE = 3
    BORDER_ROUTER = 4
    GATEWAY = 5
    SERVER_TYPES = [BEACON_SERVER, CERTIFICATE_SERVER, PATH_SERVER,
                    CONTENT_CACHE]


@unique
class NeighborType(Enum):
    """
    Defines constants for the possible types of neighbor ADs.
    """
    PARENT = 0
    CHILD = 1
    PEER = 2
    ROUTING = 3  # Inter-ISD Link


class Element(object):
    """
    Base class for elements specified in the topology file.

    Attributes:
        aid: the AD identifier of the element.
        addr: the address of the element.
    """
    def __init__(self, aid=0, addr=None):
        self.aid = aid
        self.addr = addr


class ServerElement(Element):
    """
    Represents one of the core servers in SCION.

    Attributes:
        aid: inherited from Element
        addr: inherited from Element
        type: the type of server. Possible values are listed in the ElementType
            class.
    """

    def __init__(self, aid=0, addr=None, server_type=0):
        """
        Constructor.

        Creates a new ServerElement object.

        Args:
            aid: the identifier of the AD in which the server is located.
            addr: the server address.
            type: an int representing the type of server. The possible
                values and their meanings are listed in the ElementType class.
        """
        super().__init__(self, aid, addr)
        assert server_type in ElementType.SERVER_TYPES
        self.type = server_type


class InterfaceElement(Element):
    """
    An interface between two ADs.

    An InterfaceElement represents an interface for an inter-AD connection. An
    InterfaceElement instance belongs to a RouterElement and stores relevant
    information to the interface, such as the neighbor AD and type, the local
    UDP port number, and the remote address and UDP port number.

    Attributes:
        if_id: an integer representing the interface ID.
        neighbor: an integer representing the AD or TD identifier of the
            neighbor AD.
        neighbor_type: the type of the neighbor relative to the AD to which
            this interface belongs. Possible values and their meanings are
            found in the NeighborType class.
        to_addr: a HostAddr object representing the address of the router in
            the neighboring AD to which the interface is connected.
        udp_port: an integer representing the port number of the interface's
            router used to send UDP traffic.
        to_udp_port: an integer representing the port number on the other side
            of the connection that receives UDP traffic.
    """

    def __init__(self, aid=0, addr=None, if_id=0, neighbor=0,
                 neighbor_type=0, to_addr=None, udp_port=0, to_udp_port=0):
        super().__init__(self, aid, addr)
        self.if_id = if_id
        self.neighbor = neighbor
        assert neighbor_type in map(lambda x: x.value, NeighborType)
        self.neighbor_type = neighbor_type
        self.to_addr = to_addr
        self.udp_port = udp_port
        self.to_udp_port = to_udp_port


class RouterElement(Element):
    """
    Represents a router.

    Attributes:
        interface: an InterfaceElement object representing the router's
            interface to a different AD.
    """

    def __init__(self, aid=0, addr=None, interface=None):
        super().__init__(self, aid, addr)
        self.interface = interface


class GatewayElement(Element):
    """
    Represents a gateway.

    Attributes:
        ptype: TODO (not yet implemented)
    """
    def __init__(self, aid=0, addr=None, ptype=0):
        super().__init__(self, aid, addr)
        self.ptype = ptype


class ClientElement(Element):
    """
    Represents a client.
    """
    def __init__(self, aid=0, addr=None):
        super().__init__(self, aid, addr)


class Topology(object):
    """
    Handle parsing a SCION topology XML file.

    Attributes:
        routers: a dictionary mapping neighbor types (in NeighborType) to
            lists of border routers whose interface connects to a neighbor AD
            of that type.
        servers: a dictionary mapping server types (in
            ElementType.SERVER_TYPES) to the ServerElement objects of that type
            in the topology. There can only be one of each type of server in
            the topology.
        gateways: TODO (has not yet been implemented)
        clients: a list of clients in the AD.
    """

    def __init__(self, filename=None):
        """
        Constructor.

        Construct a new Topology instance. If a topology file is specified,
        load the file and parse it to populate the lists of routers, servers,
        gateways, and clients.

        Args:
            filename: a str representing a topology file name.
        """
        self.routers = defaultdict(list)
        self.servers = {}
        self.gateways = {}
        self.clients = []

        if filename is not None:
            self.load_file(filename)
        else:
            self._filename = None
            self._topo = None

    def load_file(self, filename):
        """
        Load an XML file and creates an element tree for further parsing.

        Load and parse an XML file to create an element tree. Store the
        resulting ElementTree object internally.

        Args:
            filename: XML file to load.
        """
        assert isinstance(filename, str)
        self._filename = filename
        self._topo = ET.parse(filename)

    def parse(self):
        """
        Parse the topology ElementTree.

        Parse the internally-stored ElementTree object in order to populate the
        lists of servers, routers, clients, and gateways of the AD.
        """
        assert self._topo is not None, "Must load file first"
        self._parse_servers()
        self._parse_routers()
        self._parse_clients()
        self._parse_gateways()

    def _parse_servers(self):
        """
        Parse the servers in the topology file.
        """
        servers = self._topo.getroot().find("Servers")
        if servers is None:
            logging.info("No servers found in %s", self._filename)
            return
        for server in servers:
            element = ServerElement()
            self._parse_aid(server, element)
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
                logging.warning("Encountered unknown server tag '%s'",
                                server.tag)
                continue
            self.servers[element.type] = element

    def _parse_routers(self):
        """
        Parse the list of border routers in the topology file.

        Parse the list of border routers. Find all border router elements in
        the topology file, and add a mapping between the neighbor type of the
        border router's interface and the router itself.
        """
        routers = self._topo.getroot().find("BorderRouters")
        if routers is None:
            logging.info("No routers found in %s", self._filename)
            return
        for router in routers:
            element = RouterElement()
            self._parse_aid(router, element)
            self._parse_address(router, element)
            interfaces = router.findall("Interface")
            # SM: the following two lines imply that each router must have
            # EXACTLY one interface. If so, we should change the code below.
            assert len(interfaces) <= 1, "Router can only have one interface"
            for interface in interfaces:
                self._parse_interface(interface, element)
            self.routers[element.interface.neighbor_type].append(element)

    def _parse_clients(self):
        """
        Parse the clients in the topology file.

        Parse the clients in the topology file and populate the list of
        clients in the topology.
        """
        clients = self._topo.getroot().find("Clients")
        if clients is None:
            logging.info("No clients found in %s", self._filename)
            return
        for client in clients:
            element = ClientElement()
            self._parse_aid(client, element)
            self.clients.append(element)

    def _parse_gateways(self):
        """
        Parse the gateways in the topology file.

        Parse the gateways from the topology file and add them to the AD
        topology. TODO: finish method implementation
        """
        pass

    def _parse_aid(self, et_element, element):
        """
        Parse the AID in an element.

        Parse the AID of the XML element et_element and store the found AID in
        element.

        Args:
            et_element: an XML element (xml.etree.ElementTree.Element)
            element: the SCION Element in which to set the parsed AID.
        """
        assert ET.iselement(et_element)
        aid_el = et_element.find("AID")
        if aid_el is not None:
            element.aid = int(aid_el.text)

    def _parse_address(self, et_element, element):
        """
        Parse the address in an element.

        Parse the address of the XML element et_element and store the found
        address in element.

        Args:
            et_element: an XML element (xml.etree.ElementTree.Element)
            element: the SCION Element in which to set the parsed address.
        """
        assert ET.iselement(et_element)
        addr_type = et_element.find("AddrType").text
        addr = et_element.find("Addr").text
        to_addr = et_element.find("ToAddr")
        if addr_type.lower() == "ipv4":
            if to_addr is not None:
                element.to_addr = IPv4HostAddr(to_addr.text)
            else:
                element.addr = IPv4HostAddr(addr)
        elif addr_type.lower() == "ipv6":
            if to_addr is not None:
                element.to_addr = IPv6HostAddr(to_addr.text)
            else:
                element.addr = IPv6HostAddr(addr)
        elif addr_type.lower() == "scion":
            if to_addr is not None:
                element.to_addr = SCIONHostAddr(to_addr.text)
            else:
                element.addr = SCIONHostAddr(int(addr))
        else:
            logging.info("Unknown address type: %s", addr_type)

    def _parse_interface(self, et_element, router):
        """
        Parse an Interface element.

        Parse an Interface element from the local topology parse tree and add
        its relevant information to an InterfaceElement object associated with
        a border router in the AD.

        Args:
            et_element: an ElementTree element representing the element to
                parse.
            router: the RouterElement object with which to associate the parsed
                interface.
        """
        assert ET.iselement(et_element)
        if_el = InterfaceElement()
        if et_element.find("AddrType") is not None:
            self._parse_address(et_element, if_el)
        if_el.if_id = int(et_element.find("IFID").text)
        neighbor = et_element.find("NeighborAD")
        if neighbor is None:
            neighbor = et_element.find("NeighborTD")
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

# For testing purposes
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: %s <topofile>" % sys.argv[0])
        sys.exit()
    parser = Topology(sys.argv[1])
    parser.parse()
