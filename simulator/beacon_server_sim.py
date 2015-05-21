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

from infrastructure.beacon_server import (CoreBeaconServer, 
	LocalBeaconServer, InterfaceState)
from lib.simulator import add_element, schedule
from _collections import deque, defaultdict
from infrastructure.router import IFID_PKT_TOUT
from infrastructure.scion_elem import SCIONElement
from ipaddress import IPv4Address
from lib.crypto.certificate import CertificateChain, TRC
from lib.crypto.hash_chain import HashChain
from lib.packet.opaque_field import (OpaqueFieldType as OFT, InfoOpaqueField,
    TRCField)
from lib.packet.pcb import (PathSegment, PathConstructionBeacon)
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.path_store import PathPolicy, PathStoreRecord, PathStore
from lib.util import (read_file, write_file, get_cert_chain_file_path,
    get_sig_key_file_path)
from infrastructure.scion_elem import SCION_UDP_PORT
import base64
import threading
import datetime
import logging
import time


class CoreBeaconServerSim(CoreBeaconServer):
    """docstring for CoreBeaconServerSim"""
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
        self.path_policy = PathPolicy.from_file(path_policy_file)  # TODO: add 2 policies
        self.unverified_beacons = deque()
        self.trc_requests = {}
        self.trcs = {}
        sig_key_file = get_sig_key_file_path(self.topology.isd_id,
                                             self.topology.ad_id)
        self.signing_key = read_file(sig_key_file)
        self.signing_key = base64.b64decode(self.signing_key)
        self.if2rev_tokens = {}
        self.seg2rev_tokens = {}
        self._if_rev_token_lock = threading.Lock()

        self.ifid_state = {}
        for ifid in self.ifid2addr:
            self.ifid_state[ifid] = InterfaceState()

        self._latest_entry = 0
        # Set when we have connected and read the existing recent and incoming
        # PCBs
        # self._state_synced = threading.Event()
        # # TODO(kormat): def zookeeper host/port in topology
        # self.zk = Zookeeper(
        #     self.topology.isd_id, self.topology.ad_id,
        #     "bs", self.addr.host_addr, ["localhost:2181"],
        #     ensure_paths=(self.ZK_PCB_CACHE_PATH,))

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
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        """
        Run an instance of the Beacon Server.
        """
        logging.info('Running Core Beacon Server: %s', str(self.addr))
        schedule(0., cb=self.simulate_pcbs_propagation)
        schedule(0., cb=self.simulate_register_segments)

    def clean(self):
        pass

    def simulate_pcbs_propagation(self):
        """
        Generates a new beacon or gets ready to forward the one received.
        """
        # self._state_synced.wait()
        # if not master:
        #     logging.debug("Trying to become master")
        # if not self.zk.get_lock():
        #     if master:
        #         logging.debug("No longer master")
        #         master = False
        #     schedule(0., cb=self.simulate_pcbs_propogation, args=(master))
        # if not master:
        #     logging.debug("Became master")
        #     master = True
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

        # try:
        #     count = self.zk.expire_shared_items(
        #         self.ZK_PCB_CACHE_PATH,
        #         start_propagation - self.config.propagation_time*10)
        # except ZkConnectionLoss:
        #     schedule(0., cb=self.simulate_pcbs_propogation, args=(master))
        # if count:
        #     logging.debug("Expired %d old PCBs from shared cache", count)
        
        now = time.time()
        schedule(start_propagation + self.config.propagation_time - now
            , cb=self.simulate_pcbs_propagation)
	
    def simulate_register_segments(self):
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, leaving"
                         "register_segments")
            return

        # lock = self.zk.have_lock()
        # if not lock:
        #     logging.debug("simulate_register_segments: waiting for lock")
        # self.zk.wait_lock()
        # if not lock:
        #     logging.debug("simulate_register_segments: have lock")
        #     lock = True
        start_registration = time.time()
        self.register_core_segments()

        now = time.time()
        schedule(start_registration + self.config.registration_time - now
            , cb=self.simulate_register_segments)

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


class LocalBeaconServerSim(LocalBeaconServer):
    """docstring for LocalBeaconServerSim"""
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
        self.path_policy = PathPolicy.from_file(path_policy_file)  # TODO: add 2 policies
        self.unverified_beacons = deque()
        self.trc_requests = {}
        self.trcs = {}
        sig_key_file = get_sig_key_file_path(self.topology.isd_id,
                                             self.topology.ad_id)
        self.signing_key = read_file(sig_key_file)
        self.signing_key = base64.b64decode(self.signing_key)
        self.if2rev_tokens = {}
        self.seg2rev_tokens = {}
        self._if_rev_token_lock = threading.Lock()

        self.ifid_state = {}
        for ifid in self.ifid2addr:
            self.ifid_state[ifid] = InterfaceState()

        # self._latest_entry = 0
        # Set when we have connected and read the existing recent and incoming
        # PCBs
        # self._state_synced = threading.Event()
        # TODO(kormat): def zookeeper host/port in topology
        # self.zk = Zookeeper(
        #     self.topology.isd_id, self.topology.ad_id,
        #     "bs", self.addr.host_addr, ["localhost:2181"],
        #     ensure_paths=(self.ZK_PCB_CACHE_PATH,))

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
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        """
        Run an instance of the Local Beacon Server.
        """
        logging.info('Running Local Beacon Server: %s', str(self.addr))
        schedule(0., cb=self.simulate_pcbs_propagation)
        schedule(0., cb=self.simulate_register_segments)

    def simulate_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        # TODO: define function that dispatches the pcbs among the interfaces
        # # Wait until we have enough context to be a useful master
        # # candidate.
        # self._state_synced.wait()
        # if not master:
        #     logging.debug("Trying to become master")
        # if not self.zk.get_lock():
        #     if master:
        #         logging.debug("No longer master")
        #         master = False
        #     continue
        # if not master:
        #     logging.debug("Became master")
        #     master = True
        # try:
        #     count = self.zk.expire_shared_items(
        #         self.ZK_PCB_CACHE_PATH,
        #         start_propagation - self.config.propagation_time*10)
        # except ZkConnectionLoss:
        #     continue
        # if count:
        #     logging.debug("Expired %d old PCBs from shared cache", count)
        # sleep_interval(start_propagation, self.config.propagation_time,
        #                "PCB propagation")
        start_propagation = time.time()
        best_segments = self.beacons.get_best_segments()
        for pcb in best_segments:
            self.propagate_downstream_pcb(pcb)
        now = time.time()
        schedule(start_propagation + self.config.propagation_time - now
            , cb=self.simulate_pcbs_propagation)


    def simulate_register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, "
                         "leaving register_segments")
            return
        # lock = self.zk.have_lock()
        # if not lock:
        #     logging.debug("register_segements: waiting for lock")
        # self.zk.wait_lock()
        # if not lock:
        #     logging.debug("register_segments: have lock")
        #     lock = True
        start_registration = time.time()
        self.register_up_segments()
        self.register_down_segments()
        now = time.time()
        schedule(start_registration + self.config.registration_time - now
            , cb=self.simulate_register_segments)

    def clean(self):
        pass

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
