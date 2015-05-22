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
:mod:`beacon_server_sim` --- SCION beacon server sim
========================================
"""

import base64
import logging
import time
from _collections import deque, defaultdict
from Crypto.Hash import SHA256
from infrastructure.beacon_server import (
    CoreBeaconServer,
    LocalBeaconServer,
    InterfaceState
)
from lib.crypto.certificate import CertificateChain
from lib.crypto.hash_chain import HashChain
from lib.defines import SCION_UDP_PORT
from lib.packet.opaque_field import (
    OpaqueFieldType as OFT,
    InfoOpaqueField,
    TRCField
)
from lib.packet.pcb import PathSegment, PathConstructionBeacon
from lib.packet.scion_addr import SCIONAddr
from lib.path_store import PathPolicy, PathStore
from lib.util import (
    read_file,
    get_cert_chain_file_path,
    get_sig_key_file_path
)
from simulator.simulator import add_element, schedule


class CoreBeaconServerSim(CoreBeaconServer):
    """
    Simulator version of PathConstructionBeacon Server in a core AD
    """
    def __init__(self, addr, topo_file, config_file, path_policy_file):
        # Constructor of ScionElem
        self._addr = None
        self.topology = None
        self.config = None
        self.ifid2addr = {}
        self.parse_topology(topo_file)
        self.addr = SCIONAddr.from_values(self.topology.isd_id,
                                          self.topology.ad_id, addr)
        if config_file:
            self.parse_config(config_file)
        self.construct_ifid2addr_map()
        add_element(str(self.addr.host_addr), self)

        #Constructor of BS

        # TODO: add 2 policies
        self.path_policy = PathPolicy.from_file(path_policy_file) 
        self.unverified_beacons = deque()
        self.trc_requests = {}
        self.trcs = {}
        sig_key_file = get_sig_key_file_path(self.topology.isd_id,
                                             self.topology.ad_id)
        self.signing_key = read_file(sig_key_file)
        self.signing_key = base64.b64decode(self.signing_key)
        self.if2rev_tokens = {}
        self.seg2rev_tokens = {}

        self.ifid_state = {}
        for ifid in self.ifid2addr:
            self.ifid_state[ifid] = InterfaceState()

        self._latest_entry = 0
        # Constructor of CBS
        # Sanity check that we should indeed be a core beacon server.
        assert self.topology.is_core_ad, "This shouldn't be a core BS!"
        self.beacons = defaultdict(self._ps_factory)
        self.core_segments = defaultdict(self._ps_factory)

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
        schedule(start_propagation + self.config.propagation_time - now
            , cb=self.handle_pcbs_propagation)
	
    def register_segments(self):
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, leaving"
                         "register_segments")
            return

        start_registration = time.time()
        self.register_core_segments()

        now = time.time()
        schedule(start_registration + self.config.registration_time - now
            , cb=self.register_segments)

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
            seed = bytes("%s %d" % (self.config.master_ad_key, if_id), 'utf-8')
            start_ele = SHA256.new(seed).digest()
            chain = HashChain(start_ele)
            self.if2rev_tokens[if_id] = chain
            ret = chain.next_element()
        else:
            ret = self.if2rev_tokens[if_id].current_element()
        return ret



class LocalBeaconServerSim(LocalBeaconServer):
    """
    Simulator version of PathConstructionBeacon Server in a local AD
    """
    def __init__(self, addr, topo_file, config_file, path_policy_file):
        # Constructor of ScionElem
        self._addr = None
        self.topology = None
        self.config = None
        self.ifid2addr = {}
        self.parse_topology(topo_file)
        self.addr = SCIONAddr.from_values(self.topology.isd_id,
                                          self.topology.ad_id, addr)
        if config_file:
            self.parse_config(config_file)
        self.construct_ifid2addr_map()
        add_element(str(self.addr.host_addr), self)

        #Constructor of BS
        # TODO: add 2 policies
        self.path_policy = PathPolicy.from_file(path_policy_file)
        self.unverified_beacons = deque()
        self.trc_requests = {}
        self.trcs = {}
        sig_key_file = get_sig_key_file_path(self.topology.isd_id,
                                             self.topology.ad_id)
        self.signing_key = read_file(sig_key_file)
        self.signing_key = base64.b64decode(self.signing_key)
        self.if2rev_tokens = {}
        self.seg2rev_tokens = {}

        self.ifid_state = {}
        for ifid in self.ifid2addr:
            self.ifid_state[ifid] = InterfaceState()

        # Constructor of LBS

        # Sanity check that we should indeed be a local beacon server.
        assert not self.topology.is_core_ad, "This shouldn't be a local BS!"
        self.beacons = PathStore(self.path_policy)
        self.up_segments = PathStore(self.path_policy)
        self.down_segments = PathStore(self.path_policy)
        self.cert_chain_requests = {}
        self.cert_chains = {}
        cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
            self.topology.ad_id, self.topology.isd_id, self.topology.ad_id,
            self.config.cert_chain_version)
        self.cert_chain = CertificateChain(cert_chain_file)

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
        schedule(start_propagation + self.config.propagation_time - now
            , cb=self.handle_pcbs_propagation)


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
        schedule(start_registration + self.config.registration_time - now
            , cb=self.register_segments)

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
