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
:mod:`beacon_server` --- SCION beacon server
============================================
"""

from _collections import deque, defaultdict
from asyncio.tasks import sleep
from infrastructure.router import IFID_PKT_TOUT
from infrastructure.scion_elem import SCIONElement
from ipaddress import IPv4Address
from lib.crypto.asymcrypto import sign
from lib.crypto.certificate import verify_sig_chain_trc, CertificateChain, TRC
from lib.crypto.hash_chain import HashChain
from lib.crypto.symcrypto import gen_of_mac, get_roundkey_cache
from lib.packet.opaque_field import (OpaqueFieldType as OFT, InfoOpaqueField,
    SupportSignatureField, HopOpaqueField, SupportPCBField, SupportPeerField,
    TRCField)
from lib.packet.path_mgmt import (PathSegmentInfo, PathSegmentRecords,
    PathSegmentType as PST, PathMgmtPacket, PathMgmtType as PMT, RevocationInfo,
    RevocationPayload, RevocationType as RT)
from lib.packet.pcb import (PathSegment, ADMarking, PCBMarking, PeerMarking,
    PathConstructionBeacon)
from lib.packet.scion import (SCIONPacket, get_type, PacketType as PT,
    CertChainRequest, CertChainReply, TRCRequest, TRCReply, IFIDPacket)
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.path_store import PathPolicy, PathStoreRecord, PathStore
from lib.util import (read_file, write_file, get_cert_chain_file_path,
    get_sig_key_file_path, get_trc_file_path,
    trace, timed, sleep_interval, handle_signals)
from lib.thread import thread_safety_net
from lib.log import (init_logging, log_exception)
from lib.zookeeper import (Zookeeper, ZkConnectionLoss, ZkNoNodeError)
from Crypto.Hash import SHA256
import base64
import copy
import datetime
import logging
import os
import struct
import sys
import threading
import time


class InterfaceState(object):
    """
    Simple class that represents current state of an interface.
    """
    # Timeout for interface (link) status.
    IFID_TOUT = 3.5 * IFID_PKT_TOUT

    def __init__(self):
        self.active_from = 0
        self.active_until = 0

    def update(self):
        curr_time = time.time()
        if self.active_until + self.IFID_TOUT < curr_time:
            self.active_from = curr_time
            logging.debug('Interface (re)activated')
        self.active_until = curr_time

    def is_active(self):
        return self.active_until + self.IFID_TOUT >= time.time()


class BeaconServer(SCIONElement):
    """
    The SCION PathConstructionBeacon Server.

    Attributes:
        beacons: A FIFO queue containing the beacons for processing and
            propagation.
        if2rev_tokens: Contains the currently used revocation token
            hash-chain for each interface.
        seg2rev_tokens: Contains the currently used revocation token
            hash-chain for a path-segment.
    """
    # Amount of time units a HOF is valid (time unit is EXP_TIME_UNIT).
    HOF_EXP_TIME = 63
    # Timeout for TRC or Certificate requests.
    REQUESTS_TIMEOUT = 10
    # ZK path for incoming PCBs
    ZK_PCB_CACHE_PATH = "pcb_cache"

    def __init__(self, server_id, topo_file, config_file, path_policy_file):
        SCIONElement.__init__(self, "bs", topo_file, server_id=server_id,
                              config_file=config_file)
        # TODO: add 2 policies
        self.path_policy = PathPolicy.from_file(path_policy_file)
        self.unverified_beacons = deque()
        self.trc_requests = {}
        self.trcs = {}
        sig_key_file = get_sig_key_file_path(self.topology.isd_id,
                                             self.topology.ad_id)
        self.signing_key = read_file(sig_key_file)
        self.signing_key = base64.b64decode(self.signing_key)
        self.of_gen_key = get_roundkey_cache(bytes("%s" %
            self.config.master_ad_key, 'utf-8'))
        logging.info(self.config.__dict__)
        self.if2rev_tokens = {}
        self.seg2rev_tokens = {}
        self._if_rev_token_lock = threading.Lock()

        self.ifid_state = {}
        for ifid in self.ifid2addr:
            self.ifid_state[ifid] = InterfaceState()

        self._latest_entry = 0
        # Set when we have connected and read the existing recent and incoming
        # PCBs
        self._state_synced = threading.Event()
        # TODO(kormat): def zookeeper host/port in topology
        self.zk = Zookeeper(
            self.topology.isd_id, self.topology.ad_id,
            "bs", self.addr.host_addr, ["localhost:2181"],
            ensure_paths=(self.ZK_PCB_CACHE_PATH,))

    def _get_if_rev_token(self, if_id):
        """
        Returns the revocation token for a given interface.
        """
        self._if_rev_token_lock.acquire()
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
        self._if_rev_token_lock.release()
        return ret

    def _get_segment_rev_token(self, pcb):
        """
        Returns the revocation token for a given path-segment.

        Segments with identical hops will always use the same revocation token
        hash chain.
        """
        id = pcb.get_hops_hash()
        if id not in self.seg2rev_tokens:
            seed = bytes("%s " % self.config.master_ad_key, 'utf-8') + id
            start_ele = SHA256.new(seed).digest()
            chain = HashChain(start_ele)
            self.seg2rev_tokens[id] = chain
            return chain.next_element()
        else:
            return self.seg2rev_tokens[id].current_element()

    def propagate_downstream_pcb(self, pcb):
        """
        Propagates the beacon to all children.
        """
        assert isinstance(pcb, PathSegment)
        ingress_if = pcb.trcf.if_id
        for router_child in self.topology.child_edge_routers:
            new_pcb = copy.deepcopy(pcb)
            egress_if = router_child.interface.if_id
            new_pcb.trcf.if_id = egress_if

            last_pcbm = new_pcb.get_last_pcbm()
            if last_pcbm:
                ad_marking = self._create_ad_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp(),
                                                     last_pcbm.hof)
            else:
                ad_marking = self._create_ad_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp())

            new_pcb.add_ad(ad_marking)
            dst = SCIONAddr.from_values(self.topology.isd_id,
                                        self.topology.ad_id, router_child.addr)
            beacon = PathConstructionBeacon.from_values(self.addr.get_isd_ad(),
                                                        dst, new_pcb)
            self.send(beacon, router_child.addr)
            logging.info("Downstream PCB propagated!")

    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        pass

    def store_pcb(self, beacon):
        """
        Receives beacon and stores it for processing.
        """
        assert isinstance(beacon, PathConstructionBeacon)
        if not self.path_policy.check_filters(beacon.pcb):
            return
        segment_id = beacon.pcb.get_hops_hash(hex=True)
        try:
            self.zk.store_shared_item(
                self.ZK_PCB_CACHE_PATH,
                segment_id, beacon.pcb.pack())
        except ZkConnectionLoss:
            logging.debug("Unable to store PCB in shared path: "
                          "no connection to ZK")
            return

    def process_pcbs(self, pcbs):
        """
        Processes new beacons and appends them to beacon list.
        """
        pass

    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        pass

    def _create_ad_marking(self, ingress_if, egress_if, ts, prev_hof=None):
        """
        Creates an AD Marking with the given ingress and egress interfaces,
        timestamp, and previous HOF.
        """
        ssf = SupportSignatureField.from_values(ADMarking.LEN)
        hof = HopOpaqueField.from_values(BeaconServer.HOF_EXP_TIME,
                                         ingress_if, egress_if)
        hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
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
            hof = HopOpaqueField.from_values(BeaconServer.HOF_EXP_TIME,
                                             if_id, egress_if)
            hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
            spf = SupportPeerField.from_values(self.topology.isd_id)
            peer_marking = \
                PeerMarking.from_values(router_peer.interface.neighbor_ad,
                                        hof, spf, self._get_if_rev_token(if_id),
                                        self._get_if_rev_token(egress_if))
            data_to_sign += peer_marking.pack()
            peer_markings.append(peer_marking)
        signature = sign(data_to_sign, self.signing_key)
        return ADMarking.from_values(pcbm, peer_markings, signature)

    def handle_ifid_packet(self, ipkt):
        ifid = ipkt.reply_id
        self.ifid_state[ifid].update()

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.IFID_PKT:
            self.handle_ifid_packet(IFIDPacket(packet))
        elif ptype == PT.BEACON:
            self.store_pcb(PathConstructionBeacon(packet))
        elif ptype == PT.CERT_CHAIN_REP:
            self.process_cert_chain_rep(CertChainReply(packet))
        elif ptype == PT.TRC_REP:
            self.process_trc_rep(TRCReply(packet))
        else:
            logging.warning("Type not supported: %s", ptype)

    def run(self):
        """
        Run an instance of the Beacon Server.
        """
        threading.Thread(target=self.handle_pcbs_propagation,
                         name="BS PCB propagation",
                         daemon=True).start()
        threading.Thread(target=self.register_segments,
                         name="BS register segments",
                         daemon=True).start()
        threading.Thread(target=self.handle_shared_pcbs,
                         name="BS shared pcbs",
                         daemon=True).start()
        SCIONElement.run(self)

    def _try_to_verify_beacon(self, pcb):
        """
        Try to verify a beacon.
        """
# TODO: REMOVE THESE TWO LINES BEFORE MERGING 
        self._handle_verified_beacon(pcb)
        return
#
        assert isinstance(pcb, PathSegment)
        last_pcbm = pcb.get_last_pcbm()
        if self._check_certs_trc(last_pcbm.spcbf.isd_id, last_pcbm.ad_id,
            last_pcbm.ssf.cert_chain_version, pcb.trcf.trc_version,
            pcb.trcf.if_id):
            if self._verify_beacon(pcb):
                self._handle_verified_beacon(pcb)
            else:
                logging.warning("Invalid beacon.")
        else:
            logging.warning("Certificate(s) or TRC missing.")
            self.unverified_beacons.append(pcb)

    def _check_certs_trc(self, isd_id, ad_id, cert_chain_version, trc_version,
                         if_id):
        """
        Return True or False whether the necessary Certificate and TRC files are
        found.
        """
        pass

    def _get_trc(self, isd_id, trc_version, if_id):
        """
        Get TRC from local storage or memory.
        """
        trc = self.trcs.get((isd_id, trc_version))
        if not trc:
            # Try loading file from disk
            trc_file = get_trc_file_path(self.topology.isd_id,
                self.topology.ad_id, isd_id, trc_version)
            if os.path.exists(trc_file):
                trc = TRC(trc_file)
                self.trcs[(isd_id, trc_version)] = trc
        if not trc:
            # Requesting TRC file from cert server
            trc_tuple = (isd_id, trc_version)
            now = int(time.time())
            if (trc_tuple not in self.trc_requests or
                (now - self.trc_requests[trc_tuple] >
                BeaconServer.REQUESTS_TIMEOUT)):
                new_trc_req = TRCRequest.from_values(PT.TRC_REQ_LOCAL,
                    self.addr, if_id, self.topology.isd_id, self.topology.ad_id,
                    isd_id, trc_version)
                dst_addr = self.topology.certificate_servers[0].addr
                self.send(new_trc_req, dst_addr)
                self.trc_requests[trc_tuple] = now
                return None
        return trc

    def _verify_beacon(self, pcb):
        """
        Once the necessary certificate and TRC files have been found, verify the
        beacons.
        """
        assert isinstance(pcb, PathSegment)
        last_pcbm = pcb.get_last_pcbm()
        cert_chain_isd = last_pcbm.spcbf.isd_id
        cert_chain_ad = last_pcbm.ad_id
        cert_chain_version = last_pcbm.ssf.cert_chain_version
        trc_version = pcb.trcf.trc_version
        subject = 'ISD:' + str(cert_chain_isd) + '-AD:' + str(cert_chain_ad)
        cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
            self.topology.ad_id, cert_chain_isd, cert_chain_ad,
            cert_chain_version)
        if os.path.exists(cert_chain_file):
            chain = CertificateChain(cert_chain_file)
        else:
            chain = CertificateChain.from_values([])
        trc_file = get_trc_file_path(self.topology.isd_id, self.topology.ad_id,
            cert_chain_isd, trc_version)
        trc = TRC(trc_file)
        data_to_verify = (str(cert_chain_ad).encode('utf-8') +
                          last_pcbm.hof.pack() + last_pcbm.spcbf.pack())
        for peer_marking in pcb.ads[-1].pms:
            data_to_verify += peer_marking.pack()
        return verify_sig_chain_trc(data_to_verify, pcb.ads[-1].sig, subject,
                                    chain, trc, trc_version)

    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.
        """
        pass

    def process_trc_rep(self, trc_rep):
        """
        Process the TRC reply.
        """
        assert isinstance(trc_rep, TRCReply)
        logging.info("TRC reply received.")
        trc_file = get_trc_file_path(self.topology.isd_id, self.topology.ad_id,
            trc_rep.isd_id, trc_rep.version)
        write_file(trc_file, trc_rep.trc.decode('utf-8'))
        self.trcs[(trc_rep.isd_id, trc_rep.version)] = TRC(trc_file)
        if (trc_rep.isd_id, trc_rep.version) in self.trc_requests:
            del self.trc_requests[(trc_rep.isd_id, trc_rep.version)]
        self.handle_unverified_beacons()

    def handle_unverified_beacons(self):
        """
        Handle beacons which are waiting to be verified.
        """
        for _ in range(len(self.unverified_beacons)):
            pcb = self.unverified_beacons.popleft()
            self._try_to_verify_beacon(pcb)

    @thread_safety_net("handle_shared_pcbs")
    def handle_shared_pcbs(self):
        """
        A thread to handle Zookeeper connects/disconnects and the shared cache
        of PCBs

        On connect, it registers us as in-service, and loads the shared cache
        of PCBs from ZK, so that we have enough context should we become
        master.

        While connected, it calls _read_cached_entries() to read updated PCBS
        from the cache.
        """
        while True:
            if not self.zk.is_connected():
                self._state_synced.clear()
                self.zk.wait_connected()
            else:
                time.sleep(0.5)
            try:
                if not self._state_synced.is_set():
                    # Register that we can now accept and store PCBs in ZK
                    self.zk.join_party()
                    # Make sure we re-read the entire cache
                    self._latest_entry = 0
                count = self._read_cached_entries()
                if count:
                    logging.debug("Processed %d new/updated PCBs", count)
            except ZkConnectionLoss:
                continue
            self._state_synced.set()

    def _read_cached_entries(self):
        """
        Read new/updated entries from the shared cache and send them for
        processesing.
        """
        desc = "Fetching list of PCBs from shared cache"
        entries_meta = self.zk.get_shared_metadata(
            self.ZK_PCB_CACHE_PATH,
            timed_desc=desc)
        if not entries_meta:
            return 0
        new = []
        newest = 0
        for entry, meta in entries_meta:
            if meta.last_modified > self._latest_entry:
                new.append(entry)
            if meta.last_modified > newest:
                newest = meta.last_modified
        self._latest_entry = newest
        desc = "Processing %s new PCBs from shared path" % len(new)
        count = self._process_cached_pcbs(new, timed_desc=desc)
        return count

    @timed(1.0)
    def _process_cached_pcbs(self, entries):
        """
        Retrieve new beacons from the shared cache and send them for local
        processing.
        """
        # TODO(kormat): move constant to proper place
        chunk_size = 10
        pcbs = []
        for i in range(0, len(entries), chunk_size):
            for entry in entries[i:i+chunk_size]:
                try:
                    raw = self.zk.get_shared_item(self.ZK_PCB_CACHE_PATH,
                                                  entry)
                except ZkConnectionLoss:
                    logging.warning("Unable to retrieve PCB from shared "
                                    "cache: no connection to ZK")
                    break
                except ZkNoNodeError:
                    logging.debug("Unable to retrieve PCB from shared cache: "
                                  "no such entry (%s/%s)" %
                                  (self.ZK_PCB_CACHE_PATH, entry))
                    continue
                pcbs.append(PathSegment(raw=raw))
        self.process_pcbs(pcbs)
        return len(pcbs)


class CoreBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a core AD.

    Starts broadcasting beacons down-stream within an ISD and across ISDs
    towards other core beacon servers.
    """
    def __init__(self, server_id, topo_file, config_file, path_policy_file):
        BeaconServer.__init__(self, server_id, topo_file, config_file,
                              path_policy_file)
        # Sanity check that we should indeed be a core beacon server.
        assert self.topology.is_core_ad, "This shouldn't be a core BS!"
        self.beacons = defaultdict(self._ps_factory)
        self.core_segments = defaultdict(self._ps_factory)

    def _ps_factory(self):
        return PathStore(self.path_policy)

    def propagate_core_pcb(self, pcb):
        """
        Propagates the core beacons to other core ADs.
        """
        assert isinstance(pcb, PathSegment)
        ingress_if = pcb.trcf.if_id
        count = 0
        for core_router in self.topology.routing_edge_routers:
            new_pcb = copy.deepcopy(pcb)
            egress_if = core_router.interface.if_id
            new_pcb.trcf.if_id = egress_if
            last_pcbm = new_pcb.get_last_pcbm()
            if last_pcbm:
                ad_marking = self._create_ad_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp(),
                                                     last_pcbm.hof)
            else:
                ad_marking = self._create_ad_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp())

            new_pcb.add_ad(ad_marking)
            dst = SCIONAddr.from_values(self.topology.isd_id,
                                        self.topology.ad_id, core_router.addr)
            beacon = PathConstructionBeacon.from_values(self.addr.get_isd_ad(),
                                                        dst, new_pcb)
            self.send(beacon, core_router.addr)
            count += 1
        return count

    @thread_safety_net("handle_pcbs_propagation")
    def handle_pcbs_propagation(self):
        """
        Generates a new beacon or gets ready to forward the one received.
        """
        master = False
        while True:
            # Wait until we have enough context to be a useful master
            # candidate.
            self._state_synced.wait()
            if not master:
                logging.debug("Trying to become master")
            if not self.zk.get_lock():
                if master:
                    logging.debug("No longer master")
                    master = False
                continue
            if not master:
                logging.debug("Became master")
                master = True
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
            try:
                count = self.zk.expire_shared_items(
                    self.ZK_PCB_CACHE_PATH,
                    start_propagation - self.config.propagation_time*10)
            except ZkConnectionLoss:
                continue
            if count:
                logging.debug("Expired %d old PCBs from shared cache", count)
            sleep_interval(start_propagation, self.config.propagation_time,
                           "PCB propagation")

    @thread_safety_net("register_segments")
    def register_segments(self):
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, leaving"
                         "register_segments")
            return
        while True:
            lock = self.zk.have_lock()
            if not lock:
                logging.debug("register_segments: waiting for lock")
            self.zk.wait_lock()
            if not lock:
                logging.debug("register_segments: have lock")
                lock = True
            start_registration = time.time()
            self.register_core_segments()
            sleep_interval(start_registration, self.config.registration_time,
                           "Path registration")

    def register_core_segment(self, pcb):
        """
        Registers the core segment contained in 'pcb' with the local core path
        server.
        """
        info = PathSegmentInfo.from_values(PST.CORE,
                                           pcb.get_first_pcbm().spcbf.isd_id,
                                           self.topology.isd_id,
                                           pcb.get_first_pcbm().ad_id,
                                           self.topology.ad_id)
        pcb.remove_signatures()
        records = PathSegmentRecords.from_values(info, [pcb])
        # Register core path with local core path server.
        if self.topology.path_servers != []:
            # TODO: pick other than the first path server
            dst = SCIONAddr.from_values(self.topology.isd_id,
                                        self.topology.ad_id,
                                        self.topology.path_servers[0].addr)
            pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, None,
                                             self.addr.get_isd_ad(), dst)
            self.send(pkt, dst.host_addr)

    def process_pcbs(self, pcbs):
        """
        Processes new beacons and appends them to beacon list.
        """
        count = 0
        for pcb in pcbs:
            # Before we append the PCB for further processing we need to check
            # that it hasn't been received before.
            for ad in pcb.ads:
                if (ad.pcbm.spcbf.isd_id == self.topology.isd_id and
                        ad.pcbm.ad_id == self.topology.ad_id):
                    count += 1
                    break
            else:
                self._try_to_verify_beacon(pcb)
        if count:
            logging.debug("Dropped %d previously seen Core Segment PCBs", count)

    def _check_certs_trc(self, isd_id, ad_id, cert_chain_version, trc_version,
                         if_id):
        """
        Return True or False whether the necessary TRC file is found.
        """
        if self._get_trc(isd_id, trc_version, if_id):
            return True
        else:
            return False

    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.
        """
        isd_id = pcb.get_first_pcbm().spcbf.isd_id
        ad_id = pcb.get_first_pcbm().ad_id
        self.beacons[(isd_id, ad_id)].add_segment(pcb)
        self.core_segments[(isd_id, ad_id)].add_segment(pcb)

    def register_core_segments(self):
        """
        Register the core segment between core ADs.
        """
        core_segments = []
        for ps in self.core_segments.values():
            core_segments.extend(ps.get_best_segments())
        count = 0
        for pcb in core_segments:
            new_pcb = copy.deepcopy(pcb)
            ad_marking = self._create_ad_marking(new_pcb.trcf.if_id, 0,
                                                 new_pcb.get_timestamp(),
                                                 new_pcb.get_last_pcbm().hof)
            new_pcb.add_ad(ad_marking)
            new_pcb.segment_id = self._get_segment_rev_token(new_pcb)
            self.register_core_segment(new_pcb)
            count += 1
        logging.info("Registered %d Core paths", count)


class LocalBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a non-core AD.

    Receives, processes, and propagates beacons received by other beacon
    servers.
    """

    def __init__(self, server_id, topo_file, config_file, path_policy_file):
        BeaconServer.__init__(self, server_id, topo_file, config_file,
                              path_policy_file)
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

    def _check_certs_trc(self, isd_id, ad_id, cert_chain_version, trc_version,
                         if_id):
        """
        Return True or False whether the necessary Certificate and TRC files are
        found.
        """
        trc = self._get_trc(isd_id, trc_version, if_id)
        if trc:
            cert_chain = self.cert_chains.get((isd_id, ad_id,
                                               cert_chain_version))
            if not cert_chain:
                # Try loading file from disk
                cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
                    self.topology.ad_id, isd_id, ad_id, cert_chain_version)
                if os.path.exists(cert_chain_file):
                    cert_chain = CertificateChain(cert_chain_file)
                    self.cert_chains[(isd_id, ad_id,
                                      cert_chain_version)] = cert_chain
            if cert_chain or self.cert_chain.certs[0].issuer in trc.core_ads:
                return True
            else:
                # Requesting certificate chain file from cert server
                cert_chain_tuple = (isd_id, ad_id, cert_chain_version)
                now = int(time.time())
                if (cert_chain_tuple not in self.cert_chain_requests or
                    (now - self.cert_chain_requests[cert_chain_tuple] >
                    BeaconServer.REQUESTS_TIMEOUT)):
                    new_cert_chain_req = \
                        CertChainRequest.from_values(PT.CERT_CHAIN_REQ_LOCAL,
                            self.addr, if_id, self.topology.isd_id,
                            self.topology.ad_id, isd_id, ad_id,
                            cert_chain_version)
                    dst_addr = self.topology.certificate_servers[0].addr
                    self.send(new_cert_chain_req, dst_addr)
                    self.cert_chain_requests[cert_chain_tuple] = now
                    return False
        else:
            return False

    def register_up_segment(self, pcb):
        """
        Send up-segment to Local Path Servers
        """
        info = PathSegmentInfo.from_values(PST.UP, self.topology.isd_id,
            self.topology.isd_id, pcb.get_first_pcbm().ad_id,
            self.topology.ad_id)
        # TODO: pick other than the first path server
        dst = SCIONAddr.from_values(self.topology.isd_id,
                                    self.topology.ad_id,
                                    self.topology.path_servers[0].addr)
        records = PathSegmentRecords.from_values(info, [pcb])
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, None,
                                         self.addr.get_isd_ad(), dst)
        self.send(pkt, dst.host_addr)

    def register_down_segment(self, pcb):
        """
        Send down-segment to Core Path Server
        """
        info = PathSegmentInfo.from_values(PST.DOWN, self.topology.isd_id,
            self.topology.isd_id, pcb.get_first_pcbm().ad_id,
            self.topology.ad_id)
        core_path = pcb.get_path(reverse_direction=True)
        records = PathSegmentRecords.from_values(info, [pcb])
        dst_isd_ad = ISD_AD(pcb.get_isd(), pcb.get_first_pcbm().ad_id)
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, core_path,
                                         self.addr, dst_isd_ad)
        if_id = core_path.get_first_hop_of().ingress_if
        next_hop = self.ifid2addr[if_id]
        self.send(pkt, next_hop)

    @thread_safety_net("register_segments")
    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, "
                         "leaving register_segments")
            return
        while True:
            lock = self.zk.have_lock()
            if not lock:
                logging.debug("register_segements: waiting for lock")
            self.zk.wait_lock()
            if not lock:
                logging.debug("register_segments: have lock")
                lock = True
            start_registration = time.time()
            self.register_up_segments()
            self.register_down_segments()
            sleep_interval(start_registration, self.config.registration_time,
                           "Path registration")

    def process_pcbs(self, pcbs):
        """
        Processes new beacons and appends them to beacon list.
        """
        for pcb in pcbs:
            if self.path_policy.check_filters(pcb):
                self._try_to_verify_beacon(pcb)

    def process_cert_chain_rep(self, cert_chain_rep):
        """
        Process the Certificate chain reply.
        """
        assert isinstance(cert_chain_rep, CertChainReply)
        logging.info("Certificate chain reply received.")
        cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
            self.topology.ad_id, cert_chain_rep.isd_id, cert_chain_rep.ad_id,
            cert_chain_rep.version)
        write_file(cert_chain_file, cert_chain_rep.cert_chain.decode('utf-8'))
        self.cert_chains[(cert_chain_rep.isd_id, cert_chain_rep.ad_id,
            cert_chain_rep.version)] = CertificateChain(cert_chain_file)
        if (cert_chain_rep.isd_id, cert_chain_rep.ad_id,
            cert_chain_rep.version) in self.cert_chain_requests:
            del self.cert_chain_requests[(cert_chain_rep.isd_id,
                cert_chain_rep.ad_id, cert_chain_rep.version)]
        self.handle_unverified_beacons()

    def _process_revocation(self, rev_info):
        """
        Sends out revocation to the local PS and a CPS and down_stream BS.
        """
        assert isinstance(rev_info, RevocationInfo)
        # Build segment revocations for local path server.
        rev_infos = []
        to_remove = []
        if rev_info.rev_type == RT.DOWN_SEGMENT:
            if not self.down_segments.get_segment(rev_info.seg_id):
                logging.warning("Segment to revoke does not exist.")
                return
            info = copy.deepcopy(rev_info)
            info.rev_type = RT.UP_SEGMENT
            rev_infos.append(info)
            to_remove.append(rev_info.seg_id)
        elif rev_info.rev_type == RT.INTERFACE:
            # Go through all candidates that contain this interface token.
            for cand in (self.down_segments.candidates +
                         self.up_segments.candidates):
                if rev_info.rev_token1 in cand.pcb.get_all_iftokens():
                    to_remove.append(cand.pcb.segment_id)
                    if cand in self.up_segments.candidates:
                        info = RevocationInfo.from_values(RT.UP_SEGMENT,
                            rev_info.rev_token1, rev_info.proof1,
                            True, cand.pcb.segment_id)
                        rev_infos.append(info)
        elif rev_info.rev_type == RT.HOP:
            # Go through all candidates that contain both interface tokens.
            for cand in (self.down_segments.candidates +
                         self.up_segments.candidates):
                if (rev_info.rev_token1 in cand.pcb.get_all_iftokens() and
                    rev_info.rev_token2 in cand.pcb.get_all_iftokens()):
                    to_remove.append(cand.pcb.segment_id)
                    if cand in self.up_segments:
                        info = RevocationInfo.from_values(RT.UP_SEGMENT,
                            rev_info.rev_token1, rev_info.proof1,
                            True, cand.pcb.segment_id,
                            True, rev_info.rev_token2, rev_info.rev_token2)
                        rev_infos.append(info)

        # Remove the affected segments from the path stores.
        self.up_segments.remove_segments(to_remove)
        self.down_segments.remove_segments(to_remove)

        # Send revocations to local PS.
        if rev_infos:
            rev_payload = RevocationPayload.from_values(rev_infos)
            pkt = PathMgmtPacket.from_values(PMT.REVOCATIONS, rev_payload, None,
                                             self.addr, self.addr.get_isd_ad())
            dst = self.topology.path_servers[0].addr
            logging.info("Sending segment revocations to local PS.")
            self.send(pkt, dst)

        # Send revocation to CPS.
        if not self.up_segments.get_best_segments():
            logging.error("No up path available to send out revocation.")
            return
        up_segment = self.up_segments.get_best_segments()[0]
        assert up_segment.segment_id != rev_info.seg_id
        path = up_segment.get_path(True)
        path.up_segment_info.up_flag = True
        rev_payload = RevocationPayload.from_values([rev_info])
        dst_isd_ad = ISD_AD(up_segment.get_isd(),
                            up_segment.get_first_pcbm().ad_id)
        pkt = PathMgmtPacket.from_values(PMT.REVOCATIONS, rev_payload, path,
                                         self.addr, dst_isd_ad)
        (next_hop, port) = self.get_first_hop(pkt)
        logging.info("Sending revocation to CPS.")
        self.send(pkt, next_hop, port)

        # TODO: Propagate revocations to downstream BSes.

    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.
        """
        self.beacons.add_segment(pcb)
        self.up_segments.add_segment(pcb)
        self.down_segments.add_segment(pcb)

    @thread_safety_net("handle_pcbs_propagation")
    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        # TODO: define function that dispatches the pcbs among the interfaces
        master = False
        while True:
            # Wait until we have enough context to be a useful master
            # candidate.
            self._state_synced.wait()
            if not master:
                logging.debug("Trying to become master")
            if not self.zk.get_lock():
                if master:
                    logging.debug("No longer master")
                    master = False
                continue
            if not master:
                logging.debug("Became master")
                master = True
            start_propagation = time.time()
            best_segments = self.beacons.get_best_segments()
            for pcb in best_segments:
                self.propagate_downstream_pcb(pcb)
            try:
                count = self.zk.expire_shared_items(
                    self.ZK_PCB_CACHE_PATH,
                    start_propagation - self.config.propagation_time*10)
            except ZkConnectionLoss:
                continue
            if count:
                logging.debug("Expired %d old PCBs from shared cache", count)
            sleep_interval(start_propagation, self.config.propagation_time,
                           "PCB propagation")

    def register_up_segments(self):
        """
        Register the paths to the core.
        """
        best_segments = self.up_segments.get_best_segments()
        for pcb in best_segments:
            new_pcb = copy.deepcopy(pcb)
            ad_marking = self._create_ad_marking(new_pcb.trcf.if_id, 0,
                                                 new_pcb.get_timestamp(),
                                                 new_pcb.get_last_pcbm().hof)
            new_pcb.add_ad(ad_marking)
            new_pcb.segment_id = self._get_segment_rev_token(new_pcb)
            new_pcb.remove_signatures()
            self.register_up_segment(new_pcb)
            logging.info("Up path registered")

    def register_down_segments(self):
        """
        Register the paths from the core.
        """
        best_segments = self.down_segments.get_best_segments()
        for pcb in best_segments:
            new_pcb = copy.deepcopy(pcb)
            ad_marking = self._create_ad_marking(new_pcb.trcf.if_id, 0,
                                                 new_pcb.get_timestamp(),
                                                 new_pcb.get_last_pcbm().hof)
            new_pcb.add_ad(ad_marking)
            new_pcb.segment_id = self._get_segment_rev_token(new_pcb)
            new_pcb.remove_signatures()
            self.register_down_segment(new_pcb)
            logging.info("Down path registered")


def main():
    """
    Main function.
    """
    init_logging()
    handle_signals()
    if len(sys.argv) != 6:
        logging.error("run: %s <core|local> server_id topo_file "
                      "conf_file path_policy_file",
                      sys.argv[0])
        sys.exit()

    if sys.argv[1] == "core":
        beacon_server = CoreBeaconServer(*sys.argv[2:])
    elif sys.argv[1] == "local":
        beacon_server = LocalBeaconServer(*sys.argv[2:])
    else:
        logging.error("First parameter can only be 'local' or 'core'!")
        sys.exit()

    trace(beacon_server.id)
    logging.info("Started: %s", datetime.datetime.now())
    beacon_server.run()

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
