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
:mod:`beacon_server_sim` --- SCION beacon server(simulator)
===========================================================
"""
# Stdlib
import logging

# External packages
from Crypto.Hash import SHA256

# SCION
from infrastructure.beacon_server import (
    CoreBeaconServer,
    InterfaceState,
    LocalBeaconServer
)
from lib.crypto.hash_chain import HashChain
from lib.defines import SCION_UDP_PORT
from lib.errors import SCIONServiceLookupError
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueFieldType as OFT,
)
from lib.packet.path_mgmt import (
    IFStateInfo,
    IFStatePayload,
    PathMgmtPacket,
    PathMgmtType as PMT,
    PathSegmentInfo,
    PathSegmentRecords,
    PathSegmentType as PST,
    RevocationInfo,
)
from lib.packet.pcb import (
    ADMarking,
    PCBMarking,
    PathConstructionBeacon,
    PathSegment,
)
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.util import SCIONTime


class CoreBeaconServerSim(CoreBeaconServer):
    """
    Simulator version of PathConstructionBeacon Server in a core AD
    """
    def __init__(self, server_id, topo_file, config_file, path_policy_file,
                 simulator):
        """
        Initialises CoreBeaconServer with is_sim set to True.

        :param server_id: server identifier.
        :type server_id: int
        :param topo_file: topology file.
        :type topo_file: string
        :param config_file: configuration file.
        :type config_file: string
        :param path_policy_file: path policy file.
        :type path_policy_file: string
        :param simulator: Instance of simulator class.
        :type simulator: Simulator
        """
        CoreBeaconServer.__init__(self, server_id, topo_file, config_file,
                                  path_policy_file, is_sim=True)
        simulator.add_element(str(self.addr.host_addr), self)
        self.simulator = simulator

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        self.simulator.add_event(0., dst=str(dst),
                                 args=(packet.pack(),
                                       (str(self.addr), SCION_UDP_PORT),
                                       (str(dst), dst_port)))

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet.
        """
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        """
        Run an instance of the Beacon Server.
        """
        logging.info('Running Core Beacon Server: %s', str(self.addr))
        self.simulator.add_event(0., cb=self.handle_pcbs_propagation)
        self.simulator.add_event(0., cb=self.register_segments)
        self.simulator.add_event(0., cb=self._handle_if_timeouts)

    def clean(self):
        pass

    def handle_pcbs_propagation(self):
        """
        Generates a new beacon or gets ready to forward the one received.
        """
        start_propagation = SCIONTime.get_time()
        # Create beacon for downstream ADs.
        downstream_pcb = PathSegment()
        timestamp = int(SCIONTime.get_time())
        downstream_pcb.iof = InfoOpaqueField.from_values(
            OFT.CORE, False, timestamp, self.topology.isd_id)
        self.propagate_downstream_pcb(downstream_pcb)
        # Create beacon for core ADs.
        core_pcb = PathSegment()
        core_pcb.iof = InfoOpaqueField.from_values(
            OFT.CORE, False, timestamp, self.topology.isd_id)
        count = self.propagate_core_pcb(core_pcb)

        # Propagate received beacons. A core beacon server can only receive
        # beacons from other core beacon servers.
        beacons = []
        for ps in self.beacons.values():
            beacons.extend(ps.get_best_segments())
        for pcb in beacons:
            count += self.propagate_core_pcb(pcb)
        logging.info("Propagated %d Core PCBs", count)

        now = SCIONTime.get_time()
        self.simulator.add_event(
            start_propagation + self.config.propagation_time - now,
            cb=self.handle_pcbs_propagation
        )

    def register_segments(self):
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, leaving"
                         "register_segments")
            return

        start_registration = SCIONTime.get_time()
        self.register_core_segments()

        now = SCIONTime.get_time()
        self.simulator.add_event(
            start_registration + self.config.registration_time - now,
            cb=self.register_segments
        )

    def store_pcb(self, beacon):
        """
        Receives beacon and stores it for processing.
        """
        assert isinstance(beacon, PathConstructionBeacon)
        if not self.path_policy.check_filters(beacon.pcb):
            return
        pcbs = [beacon.pcb.pack()]
        self.process_pcbs(pcbs)

    def _check_certs_trc(self, isd_id, ad_id, cert_chain_version, trc_version,
                         if_id):
        """
        Returns True because we don't care if necessary TRC file is present
        in case of simulator.
        """
        return True

    def _verify_beacon(self, pcb):
        """
        Returns True because we don't care to verify beacons
        in case of simulator.
        """
        return True

    def _create_ad_marking(self, ingress_if, egress_if, ts, prev_hof=None):
        """
        Creates an AD Marking for given ingress and egress interfaces,
        timestamp, and previous HOF.

        :param ingress_if: ingress interface.
        :type ingress_if: int
        :param egress_if: egress interface.
        :type egress_if: int
        :param ts:
        :type ts:
        :param prev_hof:
        :type prev_hof:
        """
        hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                         ingress_if, egress_if)
        if prev_hof is None:
            hof.info = OFT.XOVR_POINT
        pcbm = PCBMarking.from_values(self.topology.isd_id, self.topology.ad_id,
                                      hof, self._get_if_rev_token(ingress_if))
        peer_markings = []
        for router_peer in self.topology.peer_edge_routers:
            if_id = router_peer.interface.if_id
            if not self.ifid_state[if_id].is_active():
                logging.warning('Peer ifid:%d inactive (not added).', if_id)
                continue
            hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                             if_id, egress_if)
            # hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
            peer_marking = \
                PCBMarking.from_values(router_peer.interface.neighbor_isd,
                                       router_peer.interface.neighbor_ad,
                                       hof, self._get_if_rev_token(if_id))
            peer_markings.append(peer_marking)
        return ADMarking.from_values(pcbm, peer_markings,
                                     self._get_if_rev_token(egress_if))

    def _handle_if_timeouts(self):
        """
        Periodically checks each interface state and issues an if revocation, if
        no keep-alive message was received for IFID_TOUT.
        """
#         start_time = SCIONTime.get_time()
#         for (if_id, if_state) in self.ifid_state.items():
#             # Check if interface has timed-out.
#             if if_state.is_expired():
#                 logging.info("Issuing revocation for IF %d.", if_id)
#                 # Issue revocation
#                 assert if_id in self.if2rev_tokens
#                 chain = self.if2rev_tokens[if_id]
#                 rev_info = RevocationInfo.from_values(
#                     RT.INTERFACE, chain.current_element(),
#                     chain.next_element())
#                 self._process_revocation(rev_info)
#                 # Advance the hash chain for the corresponding IF.
#                 try:
#                     chain.move_to_next_element()
#                 except HashChainExhausted:
#                     # TODO(shitz): Add code to handle hash chain exhaustion.
#                     logging.warning("Hash chain for IF %s is exhausted.")
#                 if_state.revoke_if_expired()
#         now = SCIONTime.get_time()
#         self.simulator.add_event(start_time + self.IF_TIMEOUT_INTERVAL - now,
#                                  cb=self._handle_if_timeouts)
        pass

    def handle_ifid_packet(self, ipkt):
        """
        Update the interface state for the corresponding interface.

        :param ipkt: The IFIDPacket.
        :type ipkt: IFIDPacket
        """
        ifid = ipkt.reply_id
        prev_state = self.ifid_state[ifid].update()
        if prev_state == InterfaceState.INACTIVE:
            logging.info("IF %d activated", ifid)
        elif prev_state in [InterfaceState.TIMED_OUT, InterfaceState.REVOKED]:
            logging.info("IF %d came back up.", ifid)

        if not prev_state == InterfaceState.ACTIVE:
            # Inform ERs about the interface coming up.
            chain = self._get_if_hash_chain(ifid)
            if chain is None:
                return
            state_info = IFStateInfo.from_values(ifid, True,
                                                 chain.next_element())
            payload = IFStatePayload.from_values([state_info])
            isd_ad = ISD_AD(self.topology.isd_id,
                            self.topology.ad_id)
            mgmt_packet = PathMgmtPacket.from_values(
                PMT.IFSTATE_INFO, payload, None, self.addr, isd_ad)
            for er in self.topology.get_all_edge_routers():
                if er.interface.if_id != ifid:
                    self.send(mgmt_packet, er.interface.addr,
                              er.interface.udp_port)

    def register_core_segment(self, pcb):
        """
        Register the core segment contained in 'pcb' with the local core path
        server.
        """
        info = PathSegmentInfo.from_values(PST.CORE,
                                           pcb.get_first_pcbm().isd_id,
                                           self.topology.isd_id,
                                           pcb.get_first_pcbm().ad_id,
                                           self.topology.ad_id)
        pcb.remove_signatures()
        records = PathSegmentRecords.from_values(info, [pcb])
        # Register core path with local core path server.
        try:
            ps_addr = self.topology.path_servers[0].addr
        except SCIONServiceLookupError:
            # If there are no local path servers, stop here.
            return
        dst = SCIONAddr.from_values(
            self.topology.isd_id, self.topology.ad_id, ps_addr)
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, None,
                                         self.addr.get_isd_ad(), dst)
        self.send(pkt, dst.host_addr)

    def _process_revocation(self, rev_info, if_id):
        """
        Removes PCBs containing a revoked interface and sends the revocation
        to the local PS.

        :param rev_info: The RevocationInfo object
        :type rev_info: RevocationInfo
        :param if_id: The if_id to be revoked (set only for if and hop rev)
        :type if_id: int
        """
        assert isinstance(rev_info, RevocationInfo)
        logging.info("Processing revocation:\n%s", str(rev_info))
        if not if_id:
            logging.error("Trying to revoke IF with ID 0.")
            return

        self._remove_revoked_pcbs(rev_info, if_id)
        # Send revocations to local PS.
        if self.topology.path_servers:
            try:
                ps_addr = self.topology.path_servers[0].addr
            except SCIONServiceLookupError:
                # If there are no local path servers, stop here.
                return
            pkt = PathMgmtPacket.from_values(PMT.REVOCATION, rev_info, None,
                                             self.addr, self.addr.get_isd_ad())
            logging.info("Sending  revocation to local PS.")
            self.send(pkt, ps_addr)


class LocalBeaconServerSim(LocalBeaconServer):
    """
    Simulator version of PathConstructionBeacon Server in a local AD
    """
    def __init__(self, server_id, topo_file, config_file, path_policy_file,
                 simulator):
        """
        Initialises LocalBeaconServer with is_sim set to True.

        :param server_id: server identifier.
        :type server_id: int
        :param topo_file: topology file.
        :type topo_file: string
        :param config_file: configuration file.
        :type config_file: string
        :param path_policy_file: path policy file.
        :type path_policy_file: string
        :param simulator: Instance of simulator class
        :type simulator: Simulator
        """
        LocalBeaconServer.__init__(self, server_id, topo_file, config_file,
                                   path_policy_file, is_sim=True)
        self.simulator = simulator
        simulator.add_element(str(self.addr.host_addr), self)

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        self.simulator.add_event(0., dst=str(dst),
                                 args=(packet.pack(),
                                       (str(self.addr), SCION_UDP_PORT),
                                       (str(dst), dst_port)))

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet
        """
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        """
        Run an instance of the Local Beacon Server.
        """
        logging.info('Running Local Beacon Server: %s', str(self.addr))
        self.simulator.add_event(0., cb=self.handle_pcbs_propagation)
        self.simulator.add_event(0., cb=self.register_segments)
        self.simulator.add_event(0., cb=self._handle_if_timeouts)

    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        start_propagation = SCIONTime.get_time()
        best_segments = self.beacons.get_best_segments()
        for pcb in best_segments:
            self.propagate_downstream_pcb(pcb)
        now = SCIONTime.get_time()
        self.simulator.add_event(
            start_propagation + self.config.propagation_time - now,
            cb=self.handle_pcbs_propagation
        )

    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, "
                         "leaving register_segments")
            return

        start_registration = SCIONTime.get_time()
        self.register_up_segments()
        self.register_down_segments()
        now = SCIONTime.get_time()
        self.simulator.add_event(
            start_registration + self.config.registration_time - now,
            cb=self.register_segments
        )

    def clean(self):
        pass

    def store_pcb(self, beacon):
        """
        Receives beacon and stores it for processing.
        """
        assert isinstance(beacon, PathConstructionBeacon)
        if not self.path_policy.check_filters(beacon.pcb):
            return
        pcbs = [beacon.pcb.pack()]
        self.process_pcbs(pcbs)

    def _check_certs_trc(self, isd_id, ad_id, cert_chain_version, trc_version,
                         if_id):
        """
        Returns True because we don't care if necessary TRC file is present
        in case of simulator.
        """
        return True

    def _verify_beacon(self, pcb):
        """
        Returns True because we don't care to verify beacons
        in case of simulator.
        """
        return True

    def _create_ad_marking(self, ingress_if, egress_if, ts, prev_hof=None):
        """
        Creates an AD Marking for given ingress and egress interfaces,
        timestamp, and previous HOF.

        :param ingress_if: ingress interface.
        :type ingress_if: int
        :param egress_if: egress interface.
        :type egress_if: int
        :param ts:
        :type ts:
        :param prev_hof:
        :type prev_hof:
        """
        hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                         ingress_if, egress_if)
        if prev_hof is None:
            hof.info = OFT.XOVR_POINT
        pcbm = PCBMarking.from_values(self.topology.isd_id, self.topology.ad_id,
                                      hof, self._get_if_rev_token(ingress_if))
        peer_markings = []
        for router_peer in self.topology.peer_edge_routers:
            if_id = router_peer.interface.if_id
            if not self.ifid_state[if_id].is_active():
                logging.warning('Peer ifid:%d inactive (not added).', if_id)
                continue
            hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                             if_id, egress_if)
            # hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
            peer_marking = \
                PCBMarking.from_values(router_peer.interface.neighbor_isd,
                                       router_peer.interface.neighbor_ad,
                                       hof, self._get_if_rev_token(if_id))
            peer_markings.append(peer_marking)
        return ADMarking.from_values(pcbm, peer_markings,
                                     self._get_if_rev_token(egress_if))

    def _handle_if_timeouts(self):
        """
        Periodically checks each interface state and issues an if revocation, if
        no keep-alive message was received for IFID_TOUT.
        """
#         start_time = SCIONTime.get_time()
#         for (if_id, if_state) in self.ifid_state.items():
#             # Check if interface has timed-out.
#             if if_state.is_expired():
#                 logging.info("Issuing revocation for IF %d.", if_id)
#                 # Issue revocation
#                 assert if_id in self.if2rev_tokens
#                 chain = self.if2rev_tokens[if_id]
#                 rev_info = RevocationInfo.from_values(
#                     RT.INTERFACE, chain.current_element(),
#                     chain.next_element())
#                 self._process_revocation(rev_info)
#                 # Advance the hash chain for the corresponding IF.
#                 try:
#                     chain.move_to_next_element()
#                 except HashChainExhausted:
#                     # TODO(shitz): Add code to handle hash chain exhaustion.
#                     logging.warning("Hash chain for IF %s is exhausted.")
#                 if_state.revoke_if_expired()
#         now = SCIONTime.get_time()
#         self.simulator.add_event(start_time + self.IF_TIMEOUT_INTERVAL - now,
#                                  cb=self._handle_if_timeouts)
        pass

    def handle_ifid_packet(self, ipkt):
        """
        Update the interface state for the corresponding interface.

        :param ipkt: The IFIDPacket.
        :type ipkt: IFIDPacket
        """
        ifid = ipkt.reply_id
        prev_state = self.ifid_state[ifid].update()
        if prev_state == InterfaceState.INACTIVE:
            logging.info("IF %d activated", ifid)
        elif prev_state in [InterfaceState.TIMED_OUT, InterfaceState.REVOKED]:
            logging.info("IF %d came back up.", ifid)

        if not prev_state == InterfaceState.ACTIVE:
            # Inform ERs about the interface coming up.
            chain = self._get_if_hash_chain(ifid)
            if chain is None:
                return
            state_info = IFStateInfo.from_values(ifid, True,
                                                 chain.next_element())
            payload = IFStatePayload.from_values([state_info])
            isd_ad = ISD_AD(self.topology.isd_id,
                            self.topology.ad_id)
            mgmt_packet = PathMgmtPacket.from_values(
                PMT.IFSTATE_INFO, payload, None, self.addr, isd_ad)
            for er in self.topology.get_all_edge_routers():
                if er.interface.if_id != ifid:
                    self.send(mgmt_packet, er.interface.addr,
                              er.interface.udp_port)

    def register_up_segment(self, pcb):
        """
        Send up-segment to Local Path Servers

        :raises:
            SCIONServiceLookupError: path server lookup failure
        """
        info = PathSegmentInfo.from_values(
            PST.UP, self.topology.isd_id, self.topology.isd_id,
            pcb.get_first_pcbm().ad_id, self.topology.ad_id)
        ps_addr = self.topology.path_servers[0].addr
        records = PathSegmentRecords.from_values(info, [pcb])
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, None,
                                         self.addr, self.addr.get_isd_ad())
        self.send(pkt, ps_addr)

    def _process_revocation(self, rev_info, if_id):
        """
        Removes PCBs containing a revoked interface and sends the revocation
        to the local PS.

        :param rev_info: The RevocationInfo object
        :type rev_info: RevocationInfo
        :param if_id: The if_id to be revoked (set only for if and hop rev)
        :type if_id: int
        """
        assert isinstance(rev_info, RevocationInfo)
        logging.info("Processing revocation:\n%s", str(rev_info))
        if not if_id:
            logging.error("Trying to revoke IF with ID 0.")
            return

        self._remove_revoked_pcbs(rev_info, if_id)
        # Send revocations to local PS.
        if self.topology.path_servers:
            try:
                ps_addr = self.topology.path_servers[0].addr
            except SCIONServiceLookupError:
                # If there are no local path servers, stop here.
                return
            pkt = PathMgmtPacket.from_values(PMT.REVOCATION, rev_info, None,
                                             self.addr, self.addr.get_isd_ad())
            logging.info("Sending  revocation to local PS.")
            self.send(pkt, ps_addr)
