# Copyright 2015 ETH Zurich
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
:mod:`router_sim` --- SCION edge router(simulator)
==================================================
"""
# Stdlib
import logging

# SCION
from infrastructure.router import Router, IFID_PKT_TOUT
from lib.defines import (
    EXP_TIME_UNIT,
    L4_UDP,
    SCION_UDP_PORT,
    SCION_UDP_EH_DATA_PORT,
)
from lib.errors import SCIONServiceLookupError
from lib.packet.host_addr import ADDR_SVC_TYPE
from lib.packet.path_mgmt import (
    PathMgmtPacket,
    PathMgmtType as PMT,
    IFStateRequest,
)
from lib.packet.scion import (
    IFIDPacket,
    PacketType as PT,
)
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.util import SCIONTime


class RouterSim(Router):
    """
    Simulator version of the SCION Router
    """
    def __init__(self, router_id, topo_file, config_file, simulator):
        """
        Initialises Router with is_sim set to True.

        :param router_id:
        :type router_id:
        :param topo_file: the topology file name.
        :type topo_file: str
        :param config_file: the configuration file name.
        :type config_file: str
        :param simulator: Instance of simulator class.
        :type simulator: Simulator
        """
        Router.__init__(self, router_id, topo_file, config_file, is_sim=True)
        self.simulator = simulator
        simulator.add_element(str(self.addr.host_addr), self)
        simulator.add_element(str(self.interface.addr), self)

    def send(self, packet, addr, port=SCION_UDP_PORT, use_local_socket=True):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        logging.info("Sending packet to %s from %s", addr, self.addr.host_addr)
        if use_local_socket:
            # SCIONElement.send(self, packet, next_hop.addr, next_hop.port)
            self.simulator.add_event(0., dst=str(addr),
                                     args=(packet.pack(),
                                           (str(self.addr), SCION_UDP_PORT),
                                           (str(addr), port)))
        else:
            self.simulator.add_event(0., dst=str(addr),
                                     args=(packet.pack(),
                                           (str(self.interface.addr),
                                            self.interface.udp_port),
                                           (str(addr), port)))

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet
        """
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        self.simulator.add_event(0., cb=self.sync_interface)
        self.simulator.add_event(0., cb=self.request_ifstates)

    def sync_interface(self):
        """
        Synchronize and initialize the router's interface with that of a
        neighboring router.
        """
        src = SCIONAddr.from_values(self.topology.isd_id, self.topology.ad_id,
                                    self.interface.addr)
        dst_isd_ad = ISD_AD(self.interface.neighbor_isd,
                            self.interface.neighbor_ad)
        ifid_req = IFIDPacket.from_values(src, dst_isd_ad,
                                          self.interface.if_id)

        self.send(ifid_req, self.interface.to_addr,
                  self.interface.to_udp_port, False)
        logging.info('Sending IFID_PKT to router: req_id:%d, rep_id:%d',
                     ifid_req.request_id, ifid_req.reply_id)

        self.simulator.add_event(IFID_PKT_TOUT, cb=self.sync_interface)

    def request_ifstates(self):
        """
        Periodically request interface states from the BS.
        """
        src = SCIONAddr.from_values(self.topology.isd_id, self.topology.ad_id,
                                    self.interface.addr)
        dst_isd_ad = ISD_AD(self.topology.isd_id, self.topology.ad_id)
        ifstates_req = IFStateRequest.from_values()
        req_pkt = PathMgmtPacket.from_values(PMT.IFSTATE_REQ, ifstates_req,
                                             None, src, dst_isd_ad)
        start_time = SCIONTime.get_time()
        logging.info("Sending IFStateRequest for all interfaces.")
        for bs in self.topology.beacon_servers:
            self.send(req_pkt, bs.addr)
        now = SCIONTime.get_time()
        self.simulator.add_event(start_time + self.IFSTATE_REQ_INTERVAL - now,
                                 cb=self.request_ifstates)

    def clean(self):
        pass

    def verify_hof(self, path, ingress=True):
        """
        Verify freshness of an opaque field.
        We do not check authentication of the MAC(simulator)

        :param hof: the hop opaque field that is verified.
        :type hof: :class:`lib.packet.opaque_field.HopOpaqueField`
        :param prev_hof: previous hop opaque field (according to order of PCB
                         propagation) required for verification.
        :type prev_hof: :class:`lib.packet.opaque_field.HopOpaqueField` or None
        :param ts: timestamp against which the opaque field is verified.
        :type ts: int
        """
        ts = path.get_iof().timestamp
        hof = path.get_hof()
        if int(SCIONTime.get_time()) <= ts + hof.exp_time * EXP_TIME_UNIT:
            return True
        else:
            logging.warning("Dropping packet due to expired OF.")
        return False

    def process_ifid_request(self, ifid_packet):
        """
        After receiving IFID_PKT from neighboring router it is completed (by
        iface information) and passed to local BSes.
        Removing DNS usage.

        :param ifid_packet: the IFID request packet to send.
        :type ifid_packet: :class:`lib.packet.scion.IFIDPacket`
        """
        # Forward 'alive' packet to all BSes (to inform that neighbor is alive).
        # BS must determine interface.
        ifid_packet.reply_id = self.interface.if_id
        try:
            # Only one BS
            bs_addr = self.topology.beacon_servers[0].addr
        except SCIONServiceLookupError as e:
            logging.error("Unable to deliver ifid packet: %s", e)
            return
        self.send(ifid_packet, bs_addr)

    def process_pcb(self, beacon, from_bs):
        """
        Depending on scenario: a) send PCB to all beacon servers, or b) to
        neighboring router.
        Removing DNS usage.

        :param beacon: The PCB.
        :type beacon: :class:`lib.packet.pcb.PathConstructionBeacon`
        :param from_bs: True, if the beacon was received from local BS.
        :type from_bs: bool
        """
        if from_bs:
            if self.interface.if_id != beacon.pcb.get_last_pcbm().hof.egress_if:
                logging.error("Wrong interface set by BS.")
                return
            self.send(beacon, self.interface.to_addr,
                      self.interface.to_udp_port, False)
        else:
            beacon.pcb.if_id = self.interface.if_id
            try:
                bs_addr = self.topology.beacon_servers[0].addr
            except SCIONServiceLookupError as e:
                logging.error("Unable to deliver PCB: %s", e)
                return
            self.send(beacon, bs_addr)

    def relay_cert_server_packet(self, spkt, from_local_ad):
        """
        Relay packets for certificate servers.
        Removing DNS usage.

        :param spkt: the SCION packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        if from_local_ad:
            addr = self.interface.to_addr
            port = self.interface.to_udp_port
        else:
            try:
                addr = self.topology.certificate_servers[0].addr
            except SCIONServiceLookupError as e:
                logging.error("Unable to deliver cert packet: %s", e)
                return
            port = SCION_UDP_PORT
        self.send(spkt, addr, port)

    def process_path_mgmt_packet(self, mgmt_pkt, from_local_ad):
        """
        Process path management packets.
        Removing DNS usage.

        :param mgmt_pkt: The path mgmt packet.
        :type mgmt_pkt: :class:`lib.packet.path_mgmt.PathMgmtPacket`
        :param from_local_ad: whether or not the packet is from the local AD.
        :type from_local_ad: bool
        """
        if mgmt_pkt.type == PMT.IFSTATE_INFO:
            # handle state update
            logging.debug("Received IFState update:\n%s",
                          str(mgmt_pkt.get_payload()))
            ifstates = mgmt_pkt.get_payload().ifstate_infos
            for ifstate in ifstates:
                self.if_states[ifstate.if_id].update(ifstate)
            return
        elif mgmt_pkt.type == PMT.REVOCATION:
            if not from_local_ad:
                # Forward to local path server if we haven't recently.
                rev_token = mgmt_pkt.get_payload().rev_token
                if (self.topology.path_servers and
                        rev_token not in self.revocations):
                    logging.debug("Forwarding revocation to local PS.")
                    logging.debug("Revocation Packet:\n%s", mgmt_pkt)
                    self.revocations[rev_token] = True
                    try:
                        ps = self.topology.path_servers[0].addr
                        self.send(mgmt_pkt, ps.addr)
                    except SCIONServiceLookupError:
                        logging.info("No local PS to forward revocation to.")

        if not from_local_ad and mgmt_pkt.hdr.get_path().is_last_path_hof():
            self.deliver(mgmt_pkt, PT.PATH_MGMT)
        else:
            self.forward_packet(mgmt_pkt, from_local_ad)

    def deliver(self, spkt, ptype):
        """
        Forwards the packet to the end destination within the current AD.

        :param spkt: The SCION Packet to forward.
        :type spkt: :class:`lib.packet.scion.SCIONPacket`
        :param ptype: The packet type.
        :type ptype: int
        """
        path = spkt.hdr.get_path()
        curr_hof = path.get_hof()
        if (not path.is_last_path_hof() or
                (curr_hof.ingress_if and curr_hof.egress_if)):
            logging.error("Trying to deliver packet that is not at the " +
                          "end of a segment:\n%s", spkt.hdr)
            return
        # Forward packet to destination.
        if ptype == PT.PATH_MGMT:
            # FIXME(PSz): that should be changed when replies are send as
            # standard data packets.
            if spkt.hdr.dst_addr.host_addr.TYPE == ADDR_SVC_TYPE:
                # Send request to any path server.
                try:
                    addr = self.topology.path_servers[0].addr
                except SCIONServiceLookupError as e:
                    logging.error("Unable to deliver path mgmt packet: %s", e)
                    return
            else:  # A response to given path server
                addr = spkt.hdr.dst_addr.host_addr
            port = SCION_UDP_PORT
        elif spkt.hdr.l4_proto == L4_UDP:
            upkt = spkt.get_payload()
            addr = spkt.hdr.dst_addr.host_addr
            port = upkt.dst_port
        else:
            addr = spkt.hdr.dst_addr.host_addr
            port = SCION_UDP_EH_DATA_PORT
        self.send(spkt, addr, port)
