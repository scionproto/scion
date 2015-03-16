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
:mod:`beacon_server` --- SCION beacon server
===========================================
"""

from _collections import deque
from asyncio.tasks import sleep
from infrastructure.scion_elem import SCIONElement
from lib.crypto.asymcrypto import sign
from lib.crypto.certificate import verify_sig_chain_trc, CertificateChain, TRC
from lib.crypto.hash_chain import HashChain
from lib.packet.host_addr import IPv4HostAddr, SCIONAddr
from lib.packet.opaque_field import (OpaqueFieldType as OFT, InfoOpaqueField,
    SupportSignatureField, HopOpaqueField, SupportPCBField, SupportPeerField,
    TRCField)
from lib.packet.path_mgmt import (PathSegmentInfo, PathSegmentRecords,
    PathSegmentType as PST, PathMgmtPacket, PathMgmtType as PMT, RevocationInfo,
    RevocationPayload, RevocationType as RT)
from lib.packet.pcb import (PathSegment, ADMarking, PCBMarking, PeerMarking,
    PathConstructionBeacon)
from lib.packet.scion import (SCIONPacket, get_type, PacketType as PT,
    CertChainRequest, CertChainReply, TRCRequest, TRCReply)
from lib.path_store import PathPolicy, PathStoreRecord, PathStore
from lib.util import (read_file, write_file, get_cert_chain_file_path,
    get_sig_key_file_path, get_trc_file_path, init_logging)
from Crypto import Random
from Crypto.Hash import SHA256
from kazoo.client import KazooClient
import base64
import datetime
import os
import sys
import threading
import time

from Crypto import Random
from Crypto.Hash import SHA256

import copy
import logging


class BeaconServer(SCIONElement):
    """
    The SCION PathConstructionBeacon Server.

    Attributes:
        beacons: A FIFO queue containing the beacons for processing and
            propagation.
        reg_queue: A FIFO queue containing paths for registration with path
            servers.
        if2rev_tokens: Contains the currently used revocation token
            hash-chain for each interface.
        seg2rev_tokens: Contains the currently used revocation token
            hash-chain for a path-segment.
    """
    # Amount of time units a HOF is valid (time unit is EXP_TIME_UNIT).
    HOF_EXP_TIME = 63
    # TODO: Make this configurable.
    BEACONS_NO = 5
    REGISTERED_PATHS = 100

    def __init__(self, addr, topo_file, config_file, path_policy_file):
        SCIONElement.__init__(self, addr, topo_file, config_file=config_file)
        self.path_policy = PathPolicy(path_policy_file)
        self.beacons = deque()
        self.reg_queue = deque()
        sig_key_file = get_sig_key_file_path(self.topology.isd_id,
                                             self.topology.ad_id)
        self.signing_key = read_file(sig_key_file)
        self.signing_key = base64.b64decode(self.signing_key)
        self.if2rev_tokens = {}
        self.seg2rev_tokens = {}

        self._init_zookeeper()

    def _init_zookeeper(self):
        self._zk = KazooClient(hosts='127.0.0.1:2181')  # TODO: def in topo?
        #TODO add listeners for connection failures
        self._zk.start()
        self._zk_sid = "bs-%d-%d" % (self.topology.isd_id, self.topology.ad_id)
        self._zk_id = "%s" % self.addr
        self._zk_propagation_lock = self._zk.Lock("/%s" % self._zk_sid,
                                                  self._zk_id)

    def _get_if_rev_token(self, if_id):
        """
        Returns the revocation token for a given interface.
        """
        if if_id == 0:
            return 32 * b"\x00"

        if if_id not in self.if2rev_tokens:
            start_ele = Random.new().read(32)
            chain = HashChain(start_ele)
            self.if2rev_tokens[if_id] = chain
            return chain.next_element()
        else:
            return self.if2rev_tokens[if_id].current_element()

    def _get_segment_rev_token(self, pcb):
        """
        Returns the revocation token for a given path-segment.

        Segments with identical hops will always use the same revocation token
        hash chain.
        """
        id = pcb.get_hops_hash()
        if id not in self.seg2rev_tokens:
            start_ele = Random.new().read(32)
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
            ad_marking = self._create_ad_marking(ingress_if, egress_if)
            new_pcb.add_ad(ad_marking)
            dst = SCIONAddr.from_values(self.topology.isd_id,
                                        self.topology.ad_id, router_child.addr)
            beacon = PathConstructionBeacon.from_values(dst, new_pcb)
            self.send(beacon, router_child.addr)
            logging.info("Downstream PCB propagated!")

    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        # TODO: define function that dispaches the pcbs among the interfaces
        while True:
            with self._zk_propagation_lock:
                while self.beacons:
                    pcb = self.beacons.popleft()
                    self.propagate_downstream_pcb(pcb)
                    self.reg_queue.append(pcb)
                time.sleep(self.config.propagation_time)

    def process_pcb(self, beacon):
        """
        Receives beacon and appends it to beacon list.
        """
        pass

    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        pass

    def _create_ad_marking(self, ingress_if, egress_if):
        """
        Creates an AD Marking with the given ingress and egress interfaces.
        """
        ssf = SupportSignatureField.from_values(ADMarking.LEN)
        hof = HopOpaqueField.from_values(BeaconServer.HOF_EXP_TIME,
                                         ingress_if, egress_if)
        spcbf = SupportPCBField.from_values(isd_id=self.topology.isd_id)
        pcbm = PCBMarking.from_values(self.topology.ad_id, ssf, hof, spcbf,
                                      self._get_if_rev_token(ingress_if),
                                      self._get_if_rev_token(egress_if))
        data_to_sign = (str(pcbm.ad_id).encode('utf-8') + pcbm.hof.pack() +
                        pcbm.spcbf.pack())
        peer_markings = []
        # TODO PSz: peering link can be only added when there is
        # IfidReply from router
        for router_peer in self.topology.peer_edge_routers:
            if_id = router_peer.interface.if_id
            hof = HopOpaqueField.from_values(BeaconServer.HOF_EXP_TIME,
                                             if_id, egress_if)
            spf = SupportPeerField.from_values(self.topology.isd_id)
            peer_marking = \
                PeerMarking.from_values(router_peer.interface.neighbor_ad,
                                        hof, spf, self._get_if_rev_token(if_id),
                                        self._get_if_rev_token(egress_if))
            data_to_sign += peer_marking.pack()
            peer_markings.append(peer_marking)
        signature = sign(data_to_sign, self.signing_key)
        return ADMarking.from_values(pcbm, peer_markings, signature)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.IFID_REQ:
            # TODO
            logging.warning("IFID_REQ received, to implement")
        elif ptype == PT.IFID_REP:
            # TODO
            logging.warning("IFID_REP received, to implement")
        elif ptype == PT.BEACON:
            self.process_pcb(PathConstructionBeacon(packet))
        else:
            logging.warning("Type not supported")

    def run(self):
        """
        Run an instance of the Beacon Server.
        """
        threading.Thread(target=self.handle_pcbs_propagation).start()
        threading.Thread(target=self.register_segments).start()
        SCIONElement.run(self)


class CoreBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a core AD.

    Starts broadcasting beacons down-stream within an ISD and across ISDs
    towards other core beacon servers.
    """
    def __init__(self, addr, topo_file, config_file, path_policy_file):
        BeaconServer.__init__(self, addr, topo_file, config_file,
                              path_policy_file)
        # Sanity check that we should indeed be a core beacon server.
        assert self.topology.is_core_ad, "This shouldn't be a core BS!"

    def propagate_core_pcb(self, pcb):
        """
        Propagates the core beacons to other core ADs.
        """
        assert isinstance(pcb, PathSegment)
        ingress_if = pcb.trcf.if_id
        for core_router in self.topology.routing_edge_routers:
            new_pcb = copy.deepcopy(pcb)
            egress_if = core_router.interface.if_id
            new_pcb.trcf.if_id = egress_if
            ad_marking = self._create_ad_marking(ingress_if, egress_if)
            new_pcb.add_ad(ad_marking)
            dst = SCIONAddr.from_values(self.topology.isd_id,
                                        self.topology.ad_id, core_router.addr)
            beacon = PathConstructionBeacon.from_values(dst, new_pcb)
            self.send(beacon, core_router.addr)
            logging.info("Core PCB propagated!")

    def handle_pcbs_propagation(self):
        """
        Generates a new beacon or gets ready to forward the one received.
        """
        while True:
            # Create beacon for downstream ADs.
            downstream_pcb = PathSegment()
            timestamp = int(time.time())
            downstream_pcb.iof = InfoOpaqueField.from_values(OFT.TDC_XOVR,
                False, timestamp, self.topology.isd_id)
            downstream_pcb.trcf = TRCField()
            self.propagate_downstream_pcb(downstream_pcb)
            # Create beacon for core ADs.
            core_pcb = PathSegment()
            core_pcb.iof = InfoOpaqueField.from_values(OFT.TDC_XOVR, False,
                                                       timestamp,
                                                       self.topology.isd_id)
            core_pcb.trcf = TRCField()
            self.propagate_core_pcb(core_pcb)
            # Propagate received beacons. A core beacon server can only receive
            # beacons from other core beacon servers.
            while self.beacons:
                pcb = self.beacons.popleft()
                self.propagate_core_pcb(pcb)
                self.reg_queue.append(pcb)
            time.sleep(self.config.propagation_time)

    def register_segments(self):
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, leaving"
                         "register_segments")
            return
        while True:
            while self.reg_queue:
                pcb = self.reg_queue.popleft()
                new_pcb = copy.deepcopy(pcb)
                ad_marking = self._create_ad_marking(new_pcb.trcf.if_id, 0)
                new_pcb.add_ad(ad_marking)
                new_pcb.segment_id = self._get_segment_rev_token(new_pcb)
                self.register_core_segment(new_pcb)
                logging.info("Paths registered")
            time.sleep(self.config.registration_time)

    def register_core_segment(self, pcb):
        """
        Registers the core segment contained in 'pcb' with the local core path
        server and the originating core path server.
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
                                             dst_addr=dst)
            logging.debug("Registering core path with local PS.")
            self.send(pkt, dst.host_addr)
        # Register core path with originating core path server.
        path = pcb.get_path(reverse_direction=True)
        # path_rec = PathSegmentRecords.from_values(self.addr, info, [pcb], path)
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, path)
        if_id = path.get_first_hop_of().ingress_if
        next_hop = self.ifid2addr[if_id]
        logging.debug("Registering core path with originating PS.")
        self.send(pkt, next_hop)

    def process_pcb(self, beacon):
        assert isinstance(beacon, PathConstructionBeacon)
        logging.info("PCB received")
        pcb = beacon.pcb
        # Before we append the PCB for further processing we need to check that
        # it hasn't been received before.
        for ad in pcb.ads:
            isd_id = ad.pcbm.spcbf.isd_id
            ad_id = ad.pcbm.ad_id
            if (isd_id == self.topology.isd_id and
                ad_id == self.topology.ad_id):
                logging.debug("Core Segment PCB already seen. Dropping...")
                return
        self.beacons.append(pcb)


class LocalBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a non-core AD.

    Receives, processes, and propagates beacons received by other beacon
    servers.
    """
    REQUESTS_TIMEOUT = 10

    def __init__(self, addr, topo_file, config_file, path_policy_file):
        BeaconServer.__init__(self, addr, topo_file, config_file,
                              path_policy_file)
        # Sanity check that we should indeed be a local beacon server.
        assert not self.topology.is_core_ad, "This shouldn't be a local BS!"
        self.unverified_beacons = deque()
        self.up_segments = PathStore(self.path_policy)
        self.down_segments = PathStore(self.path_policy)
        self.cert_chain_requests = {}
        self.trc_requests = {}
        self.cert_chains = {}
        self.trcs = {}
        cert_chain_file = get_cert_chain_file_path(self.topology.isd_id,
            self.topology.ad_id, self.topology.isd_id, self.topology.ad_id,
            self.config.cert_chain_version)
        self.cert_chain = CertificateChain(cert_chain_file)

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

    def _try_to_verify_beacon(self, pcb):
        """
        Try to verify a beacon.
        """
        assert isinstance(pcb, PathSegment)
        last_pcbm = pcb.get_last_pcbm()
        cert_chain_isd = last_pcbm.spcbf.isd_id
        cert_chain_ad = last_pcbm.ad_id
        cert_chain_version = last_pcbm.ssf.cert_chain_version
        trc_version = pcb.trcf.trc_version
        if self._check_certs_trc(cert_chain_isd, cert_chain_ad,
                                 cert_chain_version,
                                 trc_version, pcb.trcf.if_id):
            if self._verify_beacon(pcb):
                self.beacons.append(pcb)
                logging.info("Registered valid beacon.")
            else:
                logging.info("Invalid beacon.")
        else:
            logging.debug("Certificate(s) or TRC missing.")
            self.unverified_beacons.append(pcb)

    def _check_certs_trc(self, isd_id, ad_id, cert_chain_version,
                         trc_version, if_id):
        """
        Return True or False whether the necessary Certificate and TRC files are
        found.
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
                LocalBeaconServer.REQUESTS_TIMEOUT)):
                new_trc_req = TRCRequest.from_values(PT.TRC_REQ_LOCAL,
                    self.addr, if_id, self.topology.isd_id, self.topology.ad_id,
                    isd_id, trc_version)
                dst_addr = self.topology.certificate_servers[0].addr
                self.send(new_trc_req, dst_addr)
                self.trc_requests[trc_tuple] = now
                return False
        else:
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
                    LocalBeaconServer.REQUESTS_TIMEOUT)):
                    new_cert_chain_req = \
                        CertChainRequest.from_values(PT.CERT_CHAIN_REQ_LOCAL,
                            self.addr, if_id, self.topology.isd_id,
                            self.topology.ad_id, isd_id, ad_id,
                            cert_chain_version)
                    dst_addr = self.topology.certificate_servers[0].addr
                    self.send(new_cert_chain_req, dst_addr)
                    self.cert_chain_requests[cert_chain_tuple] = now
                    return False

    def _check_filters(self, pcb):
        """
        Runs some checks, including: (un)wanted ADs and min/max property values.
        """
        assert isinstance(pcb, PathSegment)
        return (self._check_unwanted_ads(pcb) and
                self._check_property_ranges(pcb))

    def _check_unwanted_ads(self, pcb):
        """
        Checks whether any of the ADs in the path belong to the black list.
        """
        for ad in pcb.ads:
            if (pcb.iof.isd_id, ad.pcbm.ad_id) in self.path_policy.unwanted_ads:
                return False
        return True

    def _check_property_ranges(self, pcb):
        """
        Checks whether any of the path properties has a value outside the
        predefined min-max range.
        """
        return (
            (self.path_policy.property_ranges['PeerLinks'][0]
             <= pcb.get_n_peer_links() <=
             self.path_policy.property_ranges['PeerLinks'][1])
            and
            (self.path_policy.property_ranges['HopsLength'][0]
             <= pcb.get_n_hops() <=
             self.path_policy.property_ranges['HopsLength'][1])
            and
            (self.path_policy.property_ranges['DelayTime'][0]
             <= int(time.time()) - pcb.get_timestamp() <=
             self.path_policy.property_ranges['DelayTime'][1])
            and
            (self.path_policy.property_ranges['GuaranteedBandwidth'][0]
             <= 10 <=
             self.path_policy.property_ranges['GuaranteedBandwidth'][1])
            and
            (self.path_policy.property_ranges['AvailableBandwidth'][0]
             <= 10 <=
             self.path_policy.property_ranges['AvailableBandwidth'][1])
            and
            (self.path_policy.property_ranges['TotalBandwidth'][0]
             <= 10 <=
             self.path_policy.property_ranges['TotalBandwidth'][1]))

    def register_up_segment(self, pcb):
        """
        Send up-segment to Local Path Servers
        """
        # Store path
        path_store_record = PathStoreRecord(pcb)
        self.up_segments.add_record(path_store_record)
        # Register path
        info = PathSegmentInfo.from_values(PST.UP, self.topology.isd_id,
            self.topology.isd_id, pcb.get_first_pcbm().ad_id,
            self.topology.ad_id)
        # TODO: pick other than the first path server
        dst = SCIONAddr.from_values(self.topology.isd_id,
                                    self.topology.ad_id,
                                    self.topology.path_servers[0].addr)
        records = PathSegmentRecords.from_values(info, [pcb])
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, None,
                                         dst_addr=dst)
        self.send(pkt, dst.host_addr)

    def register_down_segment(self, pcb):
        """
        Send down-segment to Core Path Server
        """
        # Store path
        path_store_record = PathStoreRecord(pcb)
        self.down_segments.add_record(path_store_record)
        # Register path
        info = PathSegmentInfo.from_values(PST.DOWN, self.topology.isd_id,
            self.topology.isd_id, pcb.get_first_pcbm().ad_id,
            self.topology.ad_id)
        core_path = pcb.get_path(reverse_direction=True)
        records = PathSegmentRecords.from_values(info, [pcb])
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, core_path)
        if_id = core_path.get_first_hop_of().ingress_if
        next_hop = self.ifid2addr[if_id]
        self.send(pkt, next_hop)

    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, "
                         "leaving register_segments")
            return
        while True:
            while self.reg_queue:
                pcb = self.reg_queue.popleft()
                new_pcb = copy.deepcopy(pcb)
                ad_marking = self._create_ad_marking(new_pcb.trcf.if_id, 0)
                new_pcb.add_ad(ad_marking)
                new_pcb.segment_id = self._get_segment_rev_token(new_pcb)
                new_pcb.remove_signatures()
                self.register_up_segment(new_pcb)
                self.register_down_segment(new_pcb)
                logging.info("Paths registered")
            time.sleep(self.config.registration_time)

    def process_pcb(self, beacon):
        """
        Receives beacon and appends it to beacon list.
        """
        assert isinstance(beacon, PathConstructionBeacon)
        logging.info("PCB received")
        if self._check_filters(beacon.pcb):
            self._try_to_verify_beacon(beacon.pcb)

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
                                             self.addr)
            dst = self.topology.path_servers[0].addr
            logging.info("Sending segment revocations to local PS.")
            self.send(pkt, dst)

        # Send revocation to CPS.
        if not self.up_segments.get_candidates():
            logging.error("No up path available to send out revocation.")
            return
        up_segment = self.up_segments.get_candidates()[0].pcb
        assert up_segment.segment_id != rev_info.seg_id
        path = up_segment.get_path(True)
        path.up_segment_info.up_flag = True
        rev_payload = RevocationPayload.from_values([rev_info])
        pkt = PathMgmtPacket.from_values(PMT.REVOCATIONS, rev_payload, path,
                                         self.addr)
        (next_hop, port) = self.get_first_hop(pkt)
        logging.info("Sending revocation to CPS.")
        self.send(pkt, next_hop, port)

        # TODO: Propagate revocations to downstream BSes.

    def handle_unverified_beacons(self):
        """
        Handle beacons which are waiting to be verified.
        """
        for _ in range(len(self.unverified_beacons)):
            pcb = self.unverified_beacons.popleft()
            self._try_to_verify_beacon(pcb)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.IFID_REQ:
            # TODO
            logging.warning("IFID_REQ received, to implement")
        elif ptype == PT.IFID_REP:
            # TODO
            logging.warning("IFID_REP received, to implement")
        elif ptype == PT.BEACON:
            self.process_pcb(PathConstructionBeacon(packet))
        elif ptype == PT.CERT_CHAIN_REP:
            self.process_cert_chain_rep(CertChainReply(packet))
        elif ptype == PT.TRC_REP:
            self.process_trc_rep(TRCReply(packet))
        else:
            logging.warning("Type not supported")

    def run(self):
        """
        Run an instance of the Beacon Server.
        """
        threading.Thread(target=self.handle_pcbs_propagation).start()
        threading.Thread(target=self.register_segments).start()
        SCIONElement.run(self)


def main():
    """
    Main function.
    """
    init_logging()
    if len(sys.argv) != 6:
        logging.error("run: %s <core|local> IP topo_file conf_file path_policy_file",
            sys.argv[0])
        sys.exit()

    if sys.argv[1] == "core":
        beacon_server = CoreBeaconServer(IPv4HostAddr(sys.argv[2]), sys.argv[3],
                                         sys.argv[4], sys.argv[5])
    elif sys.argv[1] == "local":
        beacon_server = LocalBeaconServer(IPv4HostAddr(sys.argv[2]),
                                          sys.argv[3], sys.argv[4], sys.argv[5])
    else:
        logging.error("First parameter can only be 'local' or 'core'!")
        sys.exit()

    logging.info("Started: %s", datetime.datetime.now())
    beacon_server.run()

if __name__ == "__main__":
    main()
