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
:mod:`beacon_server_sim` --- SCION beacon server sim
========================================
"""

import logging
import time
from Crypto.Hash import SHA256
from infrastructure.beacon_server import (
    CoreBeaconServer,
    LocalBeaconServer
)
from lib.crypto.asymcrypto import sign
from lib.crypto.hash_chain import HashChain
from lib.defines import SCION_UDP_PORT
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueFieldType as OFT,
    SupportPCBField,
    SupportPeerField,
    SupportSignatureField,
    TRCField,
)
from lib.packet.pcb import (
    ADMarking,
    PCBMarking,
    PathConstructionBeacon,
    PathSegment,
    PeerMarking,
)
from simulator.simulator import add_element, schedule


class CoreBeaconServerSim(CoreBeaconServer):
    """
    Simulator version of PathConstructionBeacon Server in a core AD
    """
    def __init__(self, server_id, topo_file, config_file, path_policy_file):
        """
        Initialises CoreBeaconServer with is_sim set to True.
        """
        CoreBeaconServer.__init__(self, server_id, topo_file, config_file,
                                  path_policy_file, is_sim=True)
        add_element(str(self.addr.host_addr), self)

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        schedule(0., dst=str(dst),
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
        Run an instance of the Beacon Server.
        """
        logging.info('Running Core Beacon Server: %s', str(self.addr))
        schedule(0., cb=self.handle_pcbs_propagation)
        schedule(0., cb=self.register_segments)

    def clean(self):
        pass

    def handle_pcbs_propagation(self):
        """
        Generates a new beacon or gets ready to forward the one received.
        """
        start_propagation = time.time()
        # Create beacon for downstream ADs.
        downstream_pcb = PathSegment()
        timestamp = int(time.time())
        downstream_pcb.iof = InfoOpaqueField.from_values(
            OFT.TDC_XOVR, False, timestamp, self.topology.isd_id)
        downstream_pcb.trcf = TRCField()
        self.propagate_downstream_pcb(downstream_pcb)
        # Create beacon for core ADs.
        core_pcb = PathSegment()
        core_pcb.iof = InfoOpaqueField.from_values(
            OFT.TDC_XOVR, False, timestamp, self.topology.isd_id)
        core_pcb.trcf = TRCField()
        count = self.propagate_core_pcb(core_pcb)

        # Propagate received beacons. A core beacon server can only receive
        # beacons from other core beacon servers.
        beacons = []
        for ps in self.beacons.values():
            beacons.extend(ps.get_best_segments())
        for pcb in beacons:
            count += self.propagate_core_pcb(pcb)
        logging.info("Propagated %d Core PCBs", count)

        now = time.time()
        schedule(start_propagation + self.config.propagation_time - now, 
                 cb=self.handle_pcbs_propagation)
	
    def register_segments(self):
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, leaving"
                         "register_segments")
            return

        start_registration = time.time()
        self.register_core_segments()

        now = time.time()
        schedule(start_registration + self.config.registration_time - now,
                 cb=self.register_segments)

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
        """
        ret = None
        if if_id == 0:
            ret = 32 * b"\x00"
        elif if_id not in self.if2rev_tokens:
            seed = bytes("%s %d" % (self.config.master_ad_key, if_id), 
                         'utf-8')
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
        timestamp, and previous HOF. Mac is not used since we are simulating.
        """
        ssf = SupportSignatureField.from_values(ADMarking.LEN)
        hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                         ingress_if, egress_if)
        if prev_hof is None:
            hof.info = OFT.LAST_OF
        # hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
        spcbf = SupportPCBField.from_values(isd_id=self.topology.isd_id)
        pcbm = PCBMarking.from_values(self.topology.ad_id, ssf, hof, spcbf,
                                      self._get_if_rev_token(ingress_if),
                                      self._get_if_rev_token(egress_if))
        data_to_sign = (str(pcbm.ad_id).encode('utf-8') + pcbm.hof.pack() +
                        pcbm.spcbf.pack())
        peer_markings = []
        for router_peer in self.topology.peer_edge_routers:
            if_id = router_peer.interface.if_id
            if not self.ifid_state[if_id].is_active():
                logging.warning('Peer ifid:%d inactive (not added).', if_id)
                continue
            hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                             if_id, egress_if)
            # hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
            spf = SupportPeerField.from_values(self.topology.isd_id)
            peer_marking = \
                PeerMarking.from_values(router_peer.interface.neighbor_ad,
                                        hof, spf, self._get_if_rev_token(if_id),
                                        self._get_if_rev_token(egress_if))
            data_to_sign += peer_marking.pack()
            peer_markings.append(peer_marking)
        signature = sign(data_to_sign, self.signing_key)
        return ADMarking.from_values(pcbm, peer_markings, signature)


class LocalBeaconServerSim(LocalBeaconServer):
    """
    Simulator version of PathConstructionBeacon Server in a local AD
    """
    def __init__(self, server_id, topo_file, config_file, path_policy_file):
        """
        Initialises LocalBeaconServer with is_sim set to True.
        """
        LocalBeaconServer.__init__(self, server_id, topo_file, config_file,
                                   path_policy_file, is_sim=True)
        add_element(str(self.addr.host_addr), self)


    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        schedule(0., dst=str(dst),
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
        schedule(0., cb=self.handle_pcbs_propagation)
        schedule(0., cb=self.register_segments)

    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        start_propagation = time.time()
        best_segments = self.beacons.get_best_segments()
        for pcb in best_segments:
            self.propagate_downstream_pcb(pcb)
        now = time.time()
        schedule(start_propagation + self.config.propagation_time - now, 
                 cb=self.handle_pcbs_propagation)


    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, "
                         "leaving register_segments")
            return

        start_registration = time.time()
        self.register_up_segments()
        self.register_down_segments()
        now = time.time()
        schedule(start_registration + self.config.registration_time - now, 
                 cb=self.register_segments)

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
        """
        ret = None
        if if_id == 0:
            ret = 32 * b"\x00"
        elif if_id not in self.if2rev_tokens:
            seed = bytes("%s %d" % (self.config.master_ad_key, if_id), 'utf-8')
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
        timestamp, and previous HOF. Mac is not used since we are simulating
        """
        ssf = SupportSignatureField.from_values(ADMarking.LEN)
        hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                         ingress_if, egress_if)
        if prev_hof is None:
            hof.info = OFT.LAST_OF
        # hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
        spcbf = SupportPCBField.from_values(isd_id=self.topology.isd_id)
        pcbm = PCBMarking.from_values(self.topology.ad_id, ssf, hof, spcbf,
                                      self._get_if_rev_token(ingress_if),
                                      self._get_if_rev_token(egress_if))
        data_to_sign = (str(pcbm.ad_id).encode('utf-8') + pcbm.hof.pack() +
                        pcbm.spcbf.pack())
        peer_markings = []
        for router_peer in self.topology.peer_edge_routers:
            if_id = router_peer.interface.if_id
            if not self.ifid_state[if_id].is_active():
                logging.warning('Peer ifid:%d inactive (not added).', if_id)
                continue
            hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                             if_id, egress_if)
            # hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
            spf = SupportPeerField.from_values(self.topology.isd_id)
            peer_marking = \
                PeerMarking.from_values(router_peer.interface.neighbor_ad,
                                        hof, spf, self._get_if_rev_token(if_id),
                                        self._get_if_rev_token(egress_if))
            data_to_sign += peer_marking.pack()
            peer_markings.append(peer_marking)
        signature = sign(data_to_sign, self.signing_key)
        return ADMarking.from_values(pcbm, peer_markings, signature)
