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
    LocalBeaconServer
)
from lib.crypto.hash_chain import HashChain, HashChainExhausted
from lib.defines import SCION_UDP_PORT
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueFieldType as OFT,
)
from lib.packet.path_mgmt import (
    RevocationInfo,
    RevocationType as RT,
)
from lib.packet.pcb import (
    ADMarking,
    PCBMarking,
    PathConstructionBeacon,
    PathSegment,
)
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
            OFT.TDC_XOVR, False, timestamp, self.topology.isd_id)
        self.propagate_downstream_pcb(downstream_pcb)
        # Create beacon for core ADs.
        core_pcb = PathSegment()
        core_pcb.iof = InfoOpaqueField.from_values(
            OFT.TDC_XOVR, False, timestamp, self.topology.isd_id)
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
        # segment_id = beacon.pcb.get_hops_hash(hex=True)
        pcb = beacon.pcb
        pcbs = []
        pcbs.append(pcb)
        self.process_pcbs(pcbs)

    def _get_if_rev_token(self, if_id):
        """
        Returns the revocation token for a given interface.

        :param if_id: interface identifier.
        :type if_id: int
        """
        ret = None
        if if_id == 0:
            ret = 32 * b"\x00"
        elif if_id not in self.if2rev_tokens:
            seed = self.config.master_ad_key + bytes("%d" % if_id, 'utf-8')
            start_ele = SHA256.new(seed).digest()
            chain = HashChain(start_ele)
            self.if2rev_tokens[if_id] = chain
            ret = chain.next_element()
        else:
            ret = self.if2rev_tokens[if_id].current_element()
        return ret

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
            hof.info = OFT.LAST_OF
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
        start_time = SCIONTime.get_time()
        for (if_id, if_state) in self.ifid_state.items():
            # Check if interface has timed-out.
            if if_state.is_expired():
                logging.info("Issuing revocation for IF %d.", if_id)
                # Issue revocation
                assert if_id in self.if2rev_tokens
                chain = self.if2rev_tokens[if_id]
                rev_info = RevocationInfo.from_values(
                    RT.INTERFACE, chain.current_element(),
                    chain.next_element())
                self._process_revocation(rev_info)
                # Advance the hash chain for the corresponding IF.
                try:
                    chain.move_to_next_element()
                except HashChainExhausted:
                    # TODO(shitz): Add code to handle hash chain exhaustion.
                    logging.warning("Hash chain for IF %s is exhausted.")
                if_state.revoke_if_expired()
        now = SCIONTime.get_time()
        self.simulator.add_event(start_time + self.IF_TIMEOUT_INTERVAL - now,
                                 cb=self._handle_if_timeouts)


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
        pcb = beacon.pcb
        pcbs = []
        pcbs.append(pcb)
        self.process_pcbs(pcbs)

    def _get_if_rev_token(self, if_id):
        """
        Returns the revocation token for a given interface.

        :param if_id: interface identifier.
        :type if_id: int
        """
        ret = None
        if if_id == 0:
            ret = 32 * b"\x00"
        elif if_id not in self.if2rev_tokens:
            seed = self.config.master_ad_key + bytes("%d" % if_id, 'utf-8')
            start_ele = SHA256.new(seed).digest()
            chain = HashChain(start_ele)
            self.if2rev_tokens[if_id] = chain
            ret = chain.next_element()
        else:
            ret = self.if2rev_tokens[if_id].current_element()
        return ret

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
            hof.info = OFT.LAST_OF
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
        start_time = SCIONTime.get_time()
        for (if_id, if_state) in self.ifid_state.items():
            # Check if interface has timed-out.
            if if_state.is_expired():
                logging.info("Issuing revocation for IF %d.", if_id)
                # Issue revocation
                assert if_id in self.if2rev_tokens
                chain = self.if2rev_tokens[if_id]
                rev_info = RevocationInfo.from_values(
                    RT.INTERFACE, chain.current_element(),
                    chain.next_element())
                self._process_revocation(rev_info)
                # Advance the hash chain for the corresponding IF.
                try:
                    chain.move_to_next_element()
                except HashChainExhausted:
                    # TODO(shitz): Add code to handle hash chain exhaustion.
                    logging.warning("Hash chain for IF %s is exhausted.")
                if_state.revoke_if_expired()
        now = SCIONTime.get_time()
        self.simulator.add_event(start_time + self.IF_TIMEOUT_INTERVAL - now,
                                 cb=self._handle_if_timeouts)
