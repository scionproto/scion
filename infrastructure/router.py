# router.py
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
:mod:`router` --- Router code
=============================

Module docstring here.

.. note::
    Fill in the docstring.

"""

from infrastructure.scion_elem import (SCIONElement, SCION_UDP_PORT,
                                       SCION_UDP_EH_DATA_PORT)
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.opaque_field import OpaqueField
from lib.packet.opaque_field import OpaqueFieldType as OFT
from lib.packet.pcb import PathConstructionBeacon
from lib.packet.scion import PacketType as PT
from lib.packet.scion import SCIONPacket, IFIDRequest, IFIDReply, get_type
import logging
import socket
import sys
import threading
import time


class NextHop(object):
    """
    Simple class for next hop representation. Object of this class corresponds
    to SCION Packet and is processed within routing context.

    :ivar addr: the next hop address.
    :vartype addr: str
    :ivar port: the next hop port number.
    :vartype port: int
    """

    def __init__(self):
        self.addr = None
        self.port = SCION_UDP_PORT

    def __str__(self):
        return "%s:%d" % (self.addr, self.port)


class Router(SCIONElement):
    """
    The SCION Router.

    :ivar addr: the router address.
    :vartype addr: :class:`HostAddr`
    :ivar topology: the AD topology as seen by the router.
    :vartype topology: :class:`Topology`
    :ivar config: the configuration of the router.
    :vartype config: :class:`Config`
    :ivar ifid2addr: a map from interface identifiers to the corresponding
       border router addresses in the server's AD.
    :vartype ifid2addr: dict
    :ivar interface: the router's inter-AD interface, if any.
    :vartype interface: :class:`lib.topology.InterfaceElement`
    :ivar pre_ext_handlers: a map of extension header types to handlers for
        those extensions that execute before routing.
    :vartype pre_ext_handlers: dict
    :ivar post_ext_handlers: a map of extension header types to handlers for
        those extensions that execute after routing.
    :vartype post_ext_handlers: dict
    """

    IFID_REQ_TOUT = 2

    def __init__(self, addr, topo_file, config_file, pre_ext_handlers=None,
                 post_ext_handlers=None):
        """
        Constructor.

        :param addr: the router address.
        :type addr: :class:`HostAddr`
        :param topo_file: the topology file name.
        :type topo_file: str
        :param config_file: the configuration file name.
        :type config_file: str
        :param pre_ext_handlers: a map of extension header types to handlers
            for those extensions that execute before routing.
        :type pre_ext_handlers: dict
        :param post_ext_handlers: a map of extension header types to handlers
            for those extensions that execute after routing.
        :type post_ext_handlers: dict

        """
        SCIONElement.__init__(self, addr, topo_file, config_file)
        self.interface = None
        for edge_router in self.topology.get_all_edge_routers():
            if edge_router.addr == self.addr:
                self.interface = edge_router.interface
                break
        assert self.interface != None
        logging.info("Interface: %s", self.interface.__dict__)
        if pre_ext_handlers:
            self.pre_ext_handlers = pre_ext_handlers
        else:
            self.pre_ext_handlers = {}
        if post_ext_handlers:
            self.post_ext_handlers = post_ext_handlers
        else:
            self.post_ext_handlers = {}
        self._remote_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._remote_socket.bind((str(self.interface.addr),
                                  self.interface.udp_port))
        self._sockets.append(self._remote_socket)
        logging.info("IP %s:%u", self.interface.addr, self.interface.udp_port)

    def run(self):
        threading.Thread(target=self.init_interface).start()
        SCIONElement.run(self)

    def send(self, packet, next_hop, use_local_socket=True):
        """
        Sends packet to next_hop.addr (class of that object must implement
        __str__ which returns IPv4 addr) using next_hop.port and local or remote
        socket.

        :param packet: the
        :type packet:
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param use_local_socket: whether to use the local socket (as opposed to
            a remote socket).
        :type use_local_socket: bool
        """
        logging.info("Sending packet to %s", next_hop)
        self.handle_extensions(packet, next_hop, False)
        if use_local_socket:
            SCIONElement.send(self, packet, next_hop.addr, next_hop.port)
        else:
            self._remote_socket.sendto(packet.pack(), (str(next_hop.addr),
                next_hop.port))

    def handle_extensions(self, spkt, next_hop, pre_routing_phase):
        """
        Handles SCION Packet extensions. Handlers can be defined for pre- and
        post-routing.
        Handler takes two parameters: packet (SCIONPacket), next_hop (NextHop).

        :param spkt:
        :type spkt:
        :param next_hop:
        :type next_hop:
        :param pre_routing_phase:
        :type pre_routing_phase:
        """
        if pre_routing_phase:
            handlers = self.pre_ext_handlers
        else:
            handlers = self.post_ext_handlers

        ext = spkt.hdr.common_hdr.next_hdr
        l = 0
        while ext and l < len(spkt.hdr.extension_hdrs):
            if ext in handlers:
                handlers[ext](spkt, next_hop)
            ext = ext.next_ext
            l += 1

        if ext or l < len(spkt.hdr.extension_hdrs):
            logging.warning("Extensions terminated incorrectly.")

    def init_interface(self):
        """
        Synchronize and initialize the router's interface with that of a
        neighboring router.
        """
        next_hop = NextHop()
        next_hop.addr = self.interface.to_addr
        next_hop.port = self.interface.to_udp_port
        ifid_req = IFIDRequest.from_values(self.interface.addr,
                self.interface.if_id)
        while True:
            self.send(ifid_req, next_hop, False)
            logging.info('IFID_REQ sent to %s', next_hop)
            time.sleep(self.IFID_REQ_TOUT)
            if self.interface.initialized:
                logging.info('Port initialized, leaving init_interface()')
                break

    def process_ifid_reply(self, packet, next_hop):
        """
        After receiving IFID_REP interface is initialized and all beacon server
        are informed.

        :param packet: the IFID reply packet to send.
        :type packet: bytes
        :param next_hop: the next hop of the reply packet.
        :type next_hop: :class:`NextHop`
        """
        logging.info('IFID_REP received, len %u', len(packet))
        ifid_rep = IFIDReply(packet)
        # TODO multiple BSs scenario
        next_hop.addr = self.topology.beacon_servers[0].addr
        ifid_rep.hdr.dst = next_hop.addr
        self.send(ifid_rep, next_hop)
        self.interface.initialized = True

    def process_ifid_request(self, packet, next_hop):
        """
        After receiving IFID_REQ from neighboring router, IFID_REP is sent back.

        :param packet: the IFID request packet to send.
        :type packet: bytes
        :param next_hop: the next hop of the request packet.
        :type next_hop: :class:`NextHop`
        """
        logging.info('IFID_REQ received, len %u', len(packet))
        ifid_req = IFIDRequest(packet)
        next_hop.addr = self.interface.to_addr
        next_hop.port = self.interface.to_udp_port
        ifid_rep = IFIDReply.from_values(next_hop.addr, self.interface.if_id,
                ifid_req.request_id)
        self.send(ifid_rep, next_hop, False)

    def process_pcb(self, packet, next_hop, from_bs):
        """
        Depending on scenario: a) sends PCB to all beacon servers, or b) to
        neighboring router.

        :param packet:
        :type packet:
        :param next_hop:
        :type next_hop:
        :param from_bs:
        :type from_bs: bool
        """
        beacon = PathConstructionBeacon(packet)
        if not self.interface.initialized:
            logging.warning("Interface not initialized.")
            return
        if from_bs:
            if self.interface.if_id != beacon.pcb.rotf.if_id:
                logging.error("Wrong interface set by BS.")
                return
            next_hop.addr = self.interface.to_addr
            next_hop.port = self.interface.to_udp_port
            self.send(beacon, next_hop, False)
        else:
            # TODO Multiple BS scenario
            beacon.pcb.rotf.if_id = self.interface.if_id
            next_hop.addr = self.topology.beacon_servers[0].addr
            self.send(beacon, next_hop)

    # TODO
    def verify_of(self, spkt):
        """
        Verifies authentication of current opaque field.

        :param spkt: the SCION packet in which to verify the opaque field.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`

        .. warning::
           This method has not yet been implemented and always returns
           ``True``.
        """
        return True

    def normal_forward(self, spkt, next_hop, from_local_ad, ptype):
        """
        Process normal forwarding.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        :param ptype: the type of the packet.
        :type ptype: :class:`lib.packet.scion.PacketType`
        """
        if not self.verify_of(spkt):
            return
        if spkt.hdr.is_on_up_path():
            iface = spkt.hdr.get_current_of().ingress_if
        else:
            iface = spkt.hdr.get_current_of().egress_if
        if from_local_ad:
            if iface == self.interface.if_id:
                next_hop.addr = self.interface.to_addr
                next_hop.port = self.interface.to_udp_port
                spkt.hdr.increase_of(1)
                self.send(spkt, next_hop, False)
            else:
                logging.error("1 interface mismatch %u != %u", iface,
                        self.interface.if_id)
        else:
            # TODO redesing Certificate Servers
            if ptype in [PT.CERT_REQ, PT.ROT_REQ, PT.CERT_REP, PT.ROT_REP]:
                next_hop.addr = \
                    self.topology.certificate_servers[0].addr
            elif iface:
                next_hop.addr = self.ifid2addr[iface]
            elif ptype in [PT.PATH_REQ, PT.PATH_REC]:
                next_hop.addr = self.topology.path_servers[0].addr
            elif not spkt.hdr.is_last_path_of(): # next path segment
                spkt.hdr.increase_of(1) # this is next SOF
                spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
                spkt.hdr.increase_of(1) # first HOF of the new path segment
                if spkt.hdr.is_on_up_path(): # TODO replace by get_first_hop
                    iface = spkt.hdr.get_current_of().ingress_if
                else:
                    iface = spkt.hdr.get_current_of().egress_if
                next_hop.addr = self.ifid2addr[iface]
            else: # last opaque field on the path, send the packet to the dst
                next_hop.addr = spkt.hdr.dst_addr
                next_hop.port = SCION_UDP_EH_DATA_PORT # data packet to endhost
            self.send(spkt, next_hop)
        logging.debug("normal_forward()")

    def crossover_forward(self, spkt, next_hop, from_local_ad, info):
        """
        Process crossover forwarding.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        :param info: the type of opaque field.
        :type info: :class:`lib.packet.opaque_field.OpaqueFieldType`
        """
        logging.debug("crossover_forward()")
        if info == OFT.TDC_XOVR:
            if self.verify_of(spkt):
                spkt.hdr.increase_of(1)
                next_iof = spkt.hdr.get_current_of()
                opaque_field = spkt.hdr.get_relative_of(1)
                if next_iof.up_flag: # TODO replace by get_first_hop
                    next_hop.addr = self.ifid2addr[opaque_field.ingress_if]
                else:
                    next_hop.addr = self.ifid2addr[opaque_field.egress_if]
                logging.debug("send() here, find next hop0.")
                self.send(spkt, next_hop)
            else:
                logging.error("Mac verification failed.")
        elif info == OFT.NON_TDC_XOVR:
            spkt.hdr.increase_of(2)
            opaque_field = spkt.hdr.get_relative_of(2)
            next_hop.addr = self.ifid2addr[opaque_field.egress_if]
            logging.debug("send() here, find next hop1")
            self.send(spkt, next_hop)
        elif info == OFT.INPATH_XOVR:
            if self.verify_of(spkt):
                is_regular = True
                while is_regular:
                    spkt.hdr.increase_of(2)
                    is_regular = spkt.hdr.get_current_of().is_regular()
                spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
                if self.verify_of(spkt):
                    logging.debug("TODO send() here, find next hop2")
        elif info == OFT.INTRATD_PEER:
            if spkt.hdr.is_on_up_path():
                spkt.hdr.increase_of(1)
            if self.verify_of(spkt):
                if not spkt.hdr.is_on_up_path():
                    spkt.hdr.increase_of(2)
                next_hop.addr = (
                        self.ifid2addr[spkt.hdr.get_current_of().ingress_if])
                logging.debug("send() here, next: %s", next_hop)
                self.send(spkt, next_hop)
        elif info == OFT.INTERTD_PEER:
            # TODO implement INTERTD_PEER
            pass
        else:
            logging.warning("Unknown case %u", info)

    def forward_packet(self, spkt, next_hop, from_local_ad, ptype):
        """
        Forward packet based on the current opaque field.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        :param ptype: the type of the packet.
        :type ptype: :class:`lib.packet.scion.PacketType`
        """
        while not spkt.hdr.get_current_of().is_regular():
            spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
            spkt.hdr.increase_of(1)

        while spkt.hdr.get_current_of().is_continue():
            spkt.hdr.increase_of(1)

        info = spkt.hdr.get_current_iof().info
        curr_iof_p = spkt.hdr.common_hdr.curr_iof_p
        # Case: peer path and first opaque field of a down path. We need to
        # increase opaque field pointer as that first opaque field is used for
        # MAC verification only.
        if (not spkt.hdr.is_on_up_path() and info == OFT.INTRATD_PEER and
            spkt.hdr.common_hdr.curr_of_p == curr_iof_p + OpaqueField.LEN):
            spkt.hdr.increase_of(1)

        # if spkt.hdr.get_current_of().is_xovr():
        if spkt.hdr.get_current_of().info == OFT.LAST_OF:
            self.crossover_forward(spkt, next_hop, from_local_ad, info)
        else:
            self.normal_forward(spkt, next_hop, from_local_ad, ptype)

    def write_to_egress_iface(self, spkt, next_hop, from_local_ad):
        """
        Forwards packet to neighboring router.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        if spkt.hdr.is_on_up_path():
            iface = spkt.hdr.get_current_of().ingress_if
        else:
            iface = spkt.hdr.get_current_of().egress_if

        info = spkt.hdr.get_current_iof().info
        spkt.hdr.increase_of(1)
        if info == OFT.INTRATD_PEER:
            of1_info = spkt.hdr.get_relative_of(1).info
            of2_info = spkt.hdr.get_current_of().info
            if ((of1_info == OFT.INTRATD_PEER and spkt.hdr.is_on_up_path()) or
                (of2_info == OFT.LAST_OF and not spkt.hdr.is_on_up_path())):
                spkt.hdr.increase_of(1)

        if self.interface.if_id != iface:  # TODO debug
            logging.error("0 interface mismatch %u != %u", iface,
                    self.interface.if_id)
            return

        next_hop.addr = self.interface.to_addr
        next_hop.port = self.interface.to_udp_port
        logging.debug("sending to dst6 %s", next_hop)
        self.send(spkt, next_hop, False)

    def process_packet(self, spkt, next_hop, from_local_ad, ptype):
        """
        Inspects current opaque fields and decides on forwarding type.

        :param spkt: the SCION packet to process.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param next_hop: the next hop of the packet.
        :type next_hop: :class:`NextHop`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        :param ptype: the type of the packet.
        :type ptype: :class:`lib.packet.scion.PacketType`
        """
        if (spkt.hdr.get_current_of() != spkt.hdr.path.get_of(0) and # TODO PSz
            ptype == PT.DATA and from_local_ad):
            of_info = spkt.hdr.get_current_of().info
            if of_info == OFT.TDC_XOVR:
                spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
                spkt.hdr.increase_of(1)
            elif of_info == OFT.NON_TDC_XOVR:
                spkt.hdr.common_hdr.curr_iof_p = spkt.hdr.common_hdr.curr_of_p
                spkt.hdr.increase_of(2)
            self.write_to_egress_iface(spkt, next_hop, from_local_ad)
        else:
            self.forward_packet(spkt, next_hop, from_local_ad, ptype)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.

        :param packet: the incoming packet to handle.
        :type packet: SCIONPacket
        :param sender:
        :type sender:
        :param from_local_socket: whether the request is coming from a local
            socket.
        :type from_local_socket: bool

        .. note::
            `sender` is not used in this function at the moment.
        """
        from_local_ad = from_local_socket
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        next_hop = NextHop()
        self.handle_extensions(spkt, next_hop, True)
        if ptype == PT.IFID_REQ and not from_local_ad:
            self.process_ifid_request(packet, next_hop)
        elif ptype == PT.IFID_REP and not from_local_ad:
            self.process_ifid_reply(packet, next_hop)
        elif ptype == PT.BEACON:
            self.process_pcb(packet, next_hop, from_local_ad)
        else:
            if ptype == PT.DATA:
                logging.debug("DATA type %u, %s", ptype, spkt)
            self.process_packet(spkt, next_hop, from_local_ad, ptype)


def main():
    """
    Initializes and starts router.
    """
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 4:
        logging.error("run: %s IP topo_file conf_file", sys.argv[0])
        sys.exit()
    router = Router(IPv4HostAddr(sys.argv[1]), sys.argv[2], sys.argv[3])
    router.run()

if __name__ == "__main__":
    main()
