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
# Stdlib
import argparse
import base64
import copy
import datetime
import logging
import os
import struct
import sys
import threading
from _collections import defaultdict, deque
from abc import ABCMeta, abstractmethod

# External packages
from Crypto.Hash import SHA256

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.asymcrypto import sign
from lib.crypto.certificate import CertificateChain, TRC, verify_sig_chain_trc
from lib.crypto.hash_chain import HashChain, HashChainExhausted
from lib.crypto.symcrypto import gen_of_mac, get_roundkey_cache
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    IFID_PKT_TOUT,
    PATH_SERVICE,
    SCION_UDP_PORT,
)
from lib.errors import SCIONServiceLookupError, SCIONIndexError
from lib.log import init_logging, log_exception
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueFieldType as OFT,
)
from lib.packet.path_mgmt import (
    IFStateInfo,
    IFStatePayload,
    IFStateRequest,
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
from lib.packet.scion import (
    CertChainReply,
    CertChainRequest,
    IFIDPacket,
    PacketType as PT,
    SCIONPacket,
    TRCReply,
    TRCRequest,
    get_type,
)
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.path_store import PathPolicy, PathStore
from lib.thread import thread_safety_net
from lib.util import (
    get_cert_chain_file_path,
    get_sig_key_file_path,
    get_trc_file_path,
    handle_signals,
    read_file,
    Raw,
    sleep_interval,
    trace,
    write_file,
    SCIONTime,
)
from lib.zookeeper import ZkNoConnection, ZkSharedCache, Zookeeper


class InterfaceState(object):
    """
    Simple class that represents current state of an interface.
    """
    # Timeout for interface (link) status.
    IFID_TOUT = 10 * IFID_PKT_TOUT

    INACTIVE = 0
    ACTIVE = 1
    TIMED_OUT = 2
    REVOKED = 3

    def __init__(self):
        """
        Initialize an instance of the class InterfaceState.
        """
        self.active_since = 0
        self.last_updated = 0
        self._state = self.INACTIVE
        self._lock = threading.RLock()

    def update(self):
        """
        Updates the state of the object.

        :returns: The previous state
        :rtype: int
        """
        with self._lock:
            curr_time = SCIONTime.get_time()
            prev_state = self._state
            if self._state != self.ACTIVE:
                self.active_since = curr_time
                self._state = self.ACTIVE
            self.last_updated = curr_time

            return prev_state

    def revoke_if_expired(self):
        """
        Sets the state of the interface to revoked.
        """
        with self._lock:
            if self._state == self.TIMED_OUT:
                self._state = self.REVOKED

    def is_active(self):
        with self._lock:
            if self._state == self.ACTIVE:
                if self.last_updated + self.IFID_TOUT >= SCIONTime.get_time():
                    return True
                self._state = self.TIMED_OUT
                return False
            return False

    def is_expired(self):
        with self._lock:
            if self._state == self.TIMED_OUT:
                return True
            elif (self._state == self.ACTIVE and
                  self.last_updated + self.IFID_TOUT < SCIONTime.get_time()):
                self._state = self.TIMED_OUT
                return True
            return False

    def is_revoked(self):
        return self._state == self.REVOKED


class RevocationObject(object):
    """
    Revocation object that gets stored to Zookeeper.
    """

    LEN = 8 + RevocationInfo.LEN

    def __init__(self, raw=None):
        self.if_id = 0
        self.hash_chain_idx = -1
        self.rev_info = None

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Parses raw bytes and populates the fields.
        """
        data = Raw(raw, "RevocationObject", self.LEN)
        (self.if_id, self.hash_chain_idx) = struct.unpack("!II", data.pop(8))
        self.rev_info = RevocationInfo(data.pop(RevocationInfo.LEN))

    def pack(self):
        """
        Returns a bytes object from the fields.
        """
        return (struct.pack("!II", self.if_id, self.hash_chain_idx) +
                self.rev_info.pack())

    @classmethod
    def from_values(cls, if_id, index, rev_token):
        """
        Returns a RevocationInfo object with the specified values.

        :param if_id: The interface id of the corresponding interface.
        :type if_id: int
        :param index: The index of the rev_token in the hash chain.
        :type index: int
        :param rev_token: revocation token of interface
        :type: bytes
        """
        rev_obj = cls()
        rev_obj.if_id = if_id
        rev_obj.hash_chain_idx = index
        rev_obj.rev_info = RevocationInfo.from_values(rev_token)

        return rev_obj


class BeaconServer(SCIONElement, metaclass=ABCMeta):
    """
    The SCION PathConstructionBeacon Server.

    Attributes:
        beacons: A FIFO queue containing the beacons for processing and
            propagation.
        if2rev_tokens: Contains the currently used revocation token
            hash-chain for each interface.
    """
    # Amount of time units a HOF is valid (time unit is EXP_TIME_UNIT).
    HOF_EXP_TIME = 63
    # Timeout for TRC or Certificate requests.
    REQUESTS_TIMEOUT = 10
    # ZK path for incoming PCBs
    ZK_PCB_CACHE_PATH = "pcb_cache"
    # ZK path for revocations.
    ZK_REVOCATIONS_PATH = "rev_cache"
    # Time revocation objects are cached in memory (in seconds).
    ZK_REV_OBJ_MAX_AGE = 60 * 60
    # Interval to checked for timed out interfaces.
    IF_TIMEOUT_INTERVAL = 1

    def __init__(self, server_id, topo_file, config_file, path_policy_file,
                 is_sim=False):
        super().__init__(BEACON_SERVICE, topo_file, server_id=server_id,
                         config_file=config_file, is_sim=is_sim)
        """
        Initialize an instance of the class BeaconServer.

        :param server_id: server identifier.
        :type server_id: int
        :param topo_file: topology file.
        :type topo_file: string
        :param config_file: configuration file.
        :type config_file: string
        :param path_policy_file: path policy file.
        :type path_policy_file: string
        :param is_sim: running on simulator
        :type is_sim: bool
        """
        # TODO: add 2 policies
        self.path_policy = PathPolicy.from_file(path_policy_file)
        self.unverified_beacons = deque()
        self.trc_requests = {}
        self.trcs = {}
        sig_key_file = get_sig_key_file_path(self.topology.isd_id,
                                             self.topology.ad_id)
        self.signing_key = read_file(sig_key_file)
        self.signing_key = base64.b64decode(self.signing_key)
        self.of_gen_key = get_roundkey_cache(self.config.master_ad_key)
        logging.info(self.config.__dict__)
        self.if2rev_tokens = {}
        self._if_rev_token_lock = threading.Lock()

        self.ifid_state = {}
        for ifid in self.ifid2addr:
            self.ifid_state[ifid] = InterfaceState()

        if not is_sim:
            # Add more IPs here if we support dual-stack
            name_addrs = "\0".join([self.id, str(SCION_UDP_PORT),
                                    str(self.addr.host_addr)])
            self.zk = Zookeeper(
                self.topology.isd_id, self.topology.ad_id, BEACON_SERVICE,
                name_addrs, self.topology.zookeepers)
            self.zk.retry("Joining party", self.zk.party_setup)
            self.pcb_cache = ZkSharedCache(
                self.zk, self.ZK_PCB_CACHE_PATH, self.process_pcbs,
                self.config.propagation_time)
            self.revobjs_cache = ZkSharedCache(
                self.zk, self.ZK_REVOCATIONS_PATH, self.process_rev_objects,
                self.ZK_REV_OBJ_MAX_AGE)

    def _init_hash_chain(self, if_id):
        """
        Setups a hash chain for interface 'if_id'.
        """
        if if_id in self.if2rev_tokens:
            return
        seed = self.config.master_ad_key + bytes("%d" % if_id, 'utf-8')
        start_ele = SHA256.new(seed).digest()
        chain = HashChain(start_ele)
        self.if2rev_tokens[if_id] = chain
        return chain

    def _get_if_hash_chain(self, if_id):
        """
        Returns the hash chain corresponding to interface if_id.
        """
        if not if_id:
            return None
        elif if_id not in self.if2rev_tokens:
            return self._init_hash_chain(if_id)

        return self.if2rev_tokens[if_id]

    def _get_if_rev_token(self, if_id):
        """
        Returns the revocation token for a given interface.

        :param if_id: interface identifier.
        :type if_id: int
        """
        self._if_rev_token_lock.acquire()
        ret = None
        if if_id == 0:
            ret = 32 * b"\x00"
        else:
            chain = self._get_if_hash_chain(if_id)
            if chain:
                ret = chain.current_element()
        self._if_rev_token_lock.release()
        return ret

    def propagate_downstream_pcb(self, pcb):
        """
        Propagates the beacon to all children.

        :param pcb: path segment.
        :type pcb: PathSegment
        """
        assert isinstance(pcb, PathSegment)
        ingress_if = pcb.if_id
        for router_child in self.topology.child_edge_routers:
            new_pcb = copy.deepcopy(pcb)
            egress_if = router_child.interface.if_id

            last_pcbm = new_pcb.get_last_pcbm()
            if last_pcbm:
                ad_marking = self._create_ad_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp(),
                                                     last_pcbm.hof)
            else:
                ad_marking = self._create_ad_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp())

            new_pcb.add_ad(ad_marking)
            self._sign_beacon(new_pcb)
            dst = SCIONAddr.from_values(self.topology.isd_id,
                                        self.topology.ad_id, router_child.addr)
            beacon = PathConstructionBeacon.from_values(self.addr.get_isd_ad(),
                                                        dst, new_pcb)
            self.send(beacon, router_child.addr)
            logging.info("Downstream PCB propagated!")

    @abstractmethod
    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        raise NotImplementedError

    def store_pcb(self, beacon):
        """
        Receives beacon and stores it for processing.

        :param pcb: path construction beacon.
        :type pcb: PathConstructionBeacon
        """
        assert isinstance(beacon, PathConstructionBeacon)
        if not self.path_policy.check_filters(beacon.pcb):
            return
        hops_hash = beacon.pcb.get_hops_hash(hex=True)
        try:
            self.pcb_cache.store(hops_hash, beacon.pcb.pack())
        except ZkNoConnection:
            logging.debug("Unable to store PCB in shared cache: "
                          "no connection to ZK")

    @abstractmethod
    def process_pcbs(self, pcbs):
        """
        Processes new beacons and appends them to beacon list.
        """
        raise NotImplementedError

    @abstractmethod
    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        raise NotImplementedError

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
        hof = HopOpaqueField.from_values(BeaconServer.HOF_EXP_TIME,
                                         ingress_if, egress_if)
        if prev_hof is None:
            hof.info = OFT.XOVR_POINT
        hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
        pcbm = PCBMarking.from_values(self.topology.isd_id, self.topology.ad_id,
                                      hof, self._get_if_rev_token(ingress_if))
        peer_markings = []
        for router_peer in self.topology.peer_edge_routers:
            if_id = router_peer.interface.if_id
            if not self.ifid_state[if_id].is_active():
                logging.warning('Peer ifid:%d inactive (not added).', if_id)
                continue
            peer_hof = HopOpaqueField.from_values(BeaconServer.HOF_EXP_TIME,
                                                  if_id, egress_if)
            peer_hof.info = OFT.XOVR_POINT
            peer_hof.mac = gen_of_mac(self.of_gen_key, peer_hof, hof, ts)
            peer_marking = \
                PCBMarking.from_values(router_peer.interface.neighbor_isd,
                                       router_peer.interface.neighbor_ad,
                                       peer_hof, self._get_if_rev_token(if_id))
            peer_markings.append(peer_marking)

        return ADMarking.from_values(pcbm, peer_markings,
                                     self._get_if_rev_token(egress_if))

    def _terminate_pcb(self, pcb):
        """
        Copies a PCB, terminates it and adds the segment ID.

        Terminating a PCB means adding a opaque field with the egress IF set
        to 0, i.e., there is no AD to forward a packet containing this path
        segment to.

        :param pcb: The PCB to terminate.
        :type pcb: PathSegment

        :returns: Terminated PCB
        :rtype: PathSegment
        """
        pcb = copy.deepcopy(pcb)
        last_hop = self._create_ad_marking(pcb.if_id, 0,
                                           pcb.get_timestamp(),
                                           pcb.get_last_pcbm().hof)
        pcb.add_ad(last_hop)
        pcb.segment_id = pcb.get_hops_hash()

        return pcb

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
            if self.zk.have_lock():
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

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.IFID_PKT:
            self.handle_ifid_packet(IFIDPacket(packet))
        elif ptype == PT.PATH_MGMT:
            self.handle_path_mgmt_packet(PathMgmtPacket(packet))
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
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="BS.worker", daemon=True).start()
        # https://github.com/netsec-ethz/scion/issues/308:
        threading.Thread(
            target=thread_safety_net, args=(self._handle_if_timeouts,),
            name="BS._handle_if_timeouts", daemon=True).start()
        super().run()

    def worker(self):
        """
        Worker thread that takes care of reading shared PCBs from ZK, and
        propagating PCBS/registering paths when master.
        """
        last_propagation = last_registration = 0
        worker_cycle = 1.0
        start = SCIONTime.get_time()
        while True:
            sleep_interval(start, worker_cycle, "BS.worker cycle")
            start = SCIONTime.get_time()
            try:
                self.zk.wait_connected()
                self.pcb_cache.process()
                self.revobjs_cache.process()
                if not self.zk.get_lock(lock_timeout=0, conn_timeout=0):
                    continue
                self.pcb_cache.expire(self.config.propagation_time * 10)
                self.revobjs_cache.expire(self.ZK_REV_OBJ_MAX_AGE * 24)
            except ZkNoConnection:
                continue
            now = SCIONTime.get_time()
            if now - last_propagation >= self.config.propagation_time:
                self.handle_pcbs_propagation()
                last_propagation = now
            if (self.config.registers_paths and
                    now - last_registration >= self.config.registration_time):
                self.register_segments()
                last_registration = now

    def _try_to_verify_beacon(self, pcb):
        """
        Try to verify a beacon.

        :param pcb: path segment to verify.
        :type pcb: PathSegment
        """
        assert isinstance(pcb, PathSegment)
        last_pcbm = pcb.get_last_pcbm()
        if self._check_certs_trc(last_pcbm.isd_id, last_pcbm.ad_id,
                                 pcb.get_last_adm().cert_ver,
                                 pcb.trc_ver, pcb.if_id):
            if self._verify_beacon(pcb):
                self._handle_verified_beacon(pcb)
            else:
                logging.warning("Invalid beacon. %s", pcb)
        else:
            logging.warning("Certificate(s) or TRC missing.")
            self.unverified_beacons.append(pcb)

    @abstractmethod
    def _check_certs_trc(self, isd_id, ad_id, cert_ver, trc_ver, if_id):
        """
        Return True or False whether the necessary Certificate and TRC files are
        found.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param cert_ver: certificate chain file version.
        :type cert_ver: int
        :param trc_ver: TRC file version.
        :type trc_ver: int
        :param if_id: interface identifier.
        :type if_id: int
        """
        raise NotImplementedError

    def _get_trc(self, isd_id, trc_ver, if_id):
        """
        Get TRC from local storage or memory.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param trc_ver: TRC file version.
        :type trc_ver: int
        :param if_id: interface identifier.
        :type if_id: int
        """
        trc = self.trcs.get((isd_id, trc_ver))
        if not trc:
            # Try loading file from disk
            trc_file = get_trc_file_path(self.topology.isd_id,
                                         self.topology.ad_id,
                                         isd_id, trc_ver)
            if os.path.exists(trc_file):
                trc = TRC(trc_file)
                self.trcs[(isd_id, trc_ver)] = trc
        if not trc:
            # Requesting TRC file from cert server
            trc_tuple = (isd_id, trc_ver)
            now = int(SCIONTime.get_time())
            if (trc_tuple not in self.trc_requests or
                (now - self.trc_requests[trc_tuple] >
                    BeaconServer.REQUESTS_TIMEOUT)):
                new_trc_req = TRCRequest.from_values(
                    PT.TRC_REQ_LOCAL, self.addr, if_id,
                    self.topology.isd_id, self.topology.ad_id,
                    isd_id, trc_ver)
                try:
                    dst_addr = self.dns_query_topo(CERTIFICATE_SERVICE)[0]
                except SCIONServiceLookupError as e:
                    logging.warning("Sending TRC request failed: %s", e)
                    return None
                self.send(new_trc_req, dst_addr)
                self.trc_requests[trc_tuple] = now
                return None
        return trc

    def _verify_beacon(self, pcb):
        """
        Once the necessary certificate and TRC files have been found, verify the
        beacons.

        :param pcb: path segment to verify.
        :type pcb: PathSegment
        """
        assert isinstance(pcb, PathSegment)
        last_pcbm = pcb.get_last_pcbm()
        cert_chain_isd = last_pcbm.isd_id
        cert_chain_ad = last_pcbm.ad_id
        cert_ver = pcb.get_last_adm().cert_ver
        trc_ver = pcb.trc_ver
        subject = 'ISD:' + str(cert_chain_isd) + '-AD:' + str(cert_chain_ad)
        cert_chain_file = get_cert_chain_file_path(
            self.topology.isd_id, self.topology.ad_id,
            cert_chain_isd, cert_chain_ad, cert_ver)
        if os.path.exists(cert_chain_file):
            chain = CertificateChain(cert_chain_file)
        else:
            chain = CertificateChain.from_values([])
        trc_file = get_trc_file_path(self.topology.isd_id, self.topology.ad_id,
                                     cert_chain_isd, trc_ver)
        trc = TRC(trc_file)

        new_pcb = copy.deepcopy(pcb)
        new_pcb.if_id = 0
        new_pcb.ads[-1].sig = b''
        new_pcb.ads[-1].sig_len = 0
        return verify_sig_chain_trc(new_pcb.pack(), pcb.ads[-1].sig, subject,
                                    chain, trc, trc_ver)

    def _sign_beacon(self, pcb):
        """
        Sign a beacon. Signature is appended to the last ADMarking.

        :param pcb: beacon to sign.
        :type pcb: PathSegment
        """
        # if_id field is excluded from signature as it is changed by ingress ERs
        if pcb.ads[-1].sig:
            logging.warning("PCB already signed.")
            return
        (pcb.if_id, tmp_if_id) = (0, pcb.if_id)
        signature = sign(pcb.pack(), self.signing_key)
        pcb.ads[-1].sig = signature
        pcb.ads[-1].sig_len = len(signature)
        pcb.if_id = tmp_if_id

    @abstractmethod
    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.

        :param pcb: verified path segment.
        :type pcb: PathSegment
        """
        raise NotImplementedError

    @abstractmethod
    def process_cert_chain_rep(self, cert_chain_rep):
        """
        Process the Certificate chain reply.
        """
        raise NotImplementedError

    def process_trc_rep(self, trc_rep):
        """
        Process the TRC reply.

        :param trc_rep: TRC reply.
        :type trc_rep: TRCReply
        """
        assert isinstance(trc_rep, TRCReply)
        logging.info("TRC reply received.")
        trc_file = get_trc_file_path(
            self.topology.isd_id, self.topology.ad_id,
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

    def process_rev_objects(self, rev_objs):
        """
        Processes revocation objects stored in Zookeeper.
        """
        for raw_obj in rev_objs:
            rev_obj = RevocationObject(raw_obj)
            chain = self._get_if_hash_chain(rev_obj.if_id)
            if chain and chain.current_index() > rev_obj.hash_chain_idx:
                try:
                    chain.set_current_index(rev_obj.hash_chain_idx)
                    logging.info("Updated hash chain index for IF %d to %d.",
                                 rev_obj.if_id, rev_obj.hash_chain_idx)
                    self._remove_revoked_pcbs(rev_obj.rev_info, rev_obj.if_id)
                except SCIONIndexError:
                    logging.warning("Rev object for IF %d contains invalid "
                                    "index: %d (1 < index < %d).",
                                    rev_obj.if_id, rev_obj.hash_chain_idx,
                                    len(chain) - 1)

    def _issue_revocation(self, if_id, chain):
        """
        Store a RevocationObject in ZK and send a revocation to all ERs.

        :param if_id: The interface that needs to be revoked.
        :type if_id: int
        :param chain: The hash chain corresponding to if_id.
        :type chain: :class:`lib.crypto.hash_chain.HashChain`
        """
        # Only the master BS issues revocations.
        if not self.zk.have_lock():
            return
        rev_info = RevocationInfo.from_values(chain.next_element())
        logging.info("Storing revocation in ZK.")
        rev_obj = RevocationObject.from_values(if_id, chain.current_index(),
                                               chain.next_element())
        self.revobjs_cache.store(chain.start_element(hex_=True),
                                 rev_obj.pack())
        logging.info("Issuing revocation for IF %d.", if_id)
        # Issue revocation to all ERs.
        info = IFStateInfo.from_values(if_id, False, chain.next_element())
        payload = IFStatePayload.from_values([info])
        isd_ad = ISD_AD(self.topology.isd_id, self.topology.ad_id)
        state_pkt = PathMgmtPacket.from_values(PMT.IFSTATE_INFO, payload,
                                               None, self.addr, isd_ad)
        for er in self.topology.get_all_edge_routers():
            self.send(state_pkt, er.interface.addr, er.interface.udp_port)
        self._process_revocation(rev_info, if_id)

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
        if self.zk.have_lock() and self.topology.path_servers:
            try:
                ps_addr = self.dns_query_topo(PATH_SERVICE)[0]
            except SCIONServiceLookupError:
                # If there are no local path servers, stop here.
                return
            pkt = PathMgmtPacket.from_values(PMT.REVOCATION, rev_info, None,
                                             self.addr, self.addr.get_isd_ad())
            logging.info("Sending  revocation to local PS.")
            self.send(pkt, ps_addr)

    @abstractmethod
    def _remove_revoked_pcbs(self, rev_info, if_id):
        """
        Removes the PCBs containing the revoked interface.

        :param rev_info: The RevocationInfo object.
        :type rev_info: RevocationInfo
        :param if_id: The if_id to be revoked
        :type if_id: int
        """
        raise NotImplementedError

    def _handle_if_timeouts(self):
        """
        Periodically checks each interface state and issues an if revocation, if
        no keep-alive message was received for IFID_TOUT.
        """
        while True:
            start_time = SCIONTime.get_time()
            for (if_id, if_state) in self.ifid_state.items():
                # Check if interface has timed-out.
                if if_state.is_expired():
                    logging.info("IF %d appears to be down.", if_id)
                    if if_id not in self.if2rev_tokens:
                        logging.error("Trying to issue revocation for " +
                                      "non-existent if ID %d.", if_id)
                        continue
                    chain = self.if2rev_tokens[if_id]
                    self._issue_revocation(if_id, chain)
                    # Advance the hash chain for the corresponding IF.
                    try:
                        chain.move_to_next_element()
                    except HashChainExhausted:
                        # TODO(shitz): Add code to handle hash chain
                        # exhaustion.
                        logging.warning("HashChain for IF %s is exhausted.")
                    if_state.revoke_if_expired()
            sleep_interval(start_time, self.IF_TIMEOUT_INTERVAL,
                           "Handle IF timeouts")

    def handle_path_mgmt_packet(self, mgmt_pkt):
        """
        Handles PathMgmt packets.
        """
        if mgmt_pkt.type == PMT.IFSTATE_REQ:
            self._handle_ifstate_request(mgmt_pkt)
        else:
            logging.error("Received unsupported PathMgmt packet (type %d).",
                          mgmt_pkt.type)

    def _handle_ifstate_request(self, mgmt_pkt):
        """
        Handles IFStateRequests.

        :param mgmt_pkt: The packet containing the IFStateRequest.
        :type request: :class:`lib.packet.path_mgmt.PathMgmtPacket`
        """
        # Only master replies to ifstate requests.
        if not self.zk.have_lock():
            return
        request = mgmt_pkt.get_payload()
        assert isinstance(request, IFStateRequest)
        logging.debug("Received ifstate req:\n%s", mgmt_pkt)
        infos = []
        if request.if_id == IFStateRequest.ALL_INTERFACES:
            for (ifid, state) in self.ifid_state.items():
                chain = self._get_if_hash_chain(ifid)
                info = IFStateInfo.from_values(ifid, state.is_active(),
                                               chain.next_element())
                infos.append(info)
        elif request.if_id in self.ifid_state:
            chain = self._get_if_hash_chain(request.if_id)
            state = self.ifid_state[request.if_id]
            info = IFStateInfo.from_values(ifid, state.is_active(),
                                           chain.next_element())
            infos.append(info)
        else:
            logging.error("Received ifstate request from %s for unknown "
                          "interface %d.", mgmt_pkt.hdr.src_addr, request.if_id)

        if infos:
            payload = IFStatePayload.from_values(infos)
            isd_ad = ISD_AD(self.topology.isd_id, self.topology.ad_id)
            state_pkt = PathMgmtPacket.from_values(PMT.IFSTATE_INFO, payload,
                                                   None, self.addr, isd_ad)
            for er in self.topology.get_all_edge_routers():
                if er.interface.addr == mgmt_pkt.hdr.src_addr.host_addr:
                    self.send(state_pkt, er.interface.addr,
                              er.interface.udp_port)
                    break


class CoreBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a core AD.

    Starts broadcasting beacons down-stream within an ISD and across ISDs
    towards other core beacon servers.
    """
    def __init__(self, server_id, topo_file, config_file, path_policy_file,
                 is_sim=False):
        BeaconServer.__init__(self, server_id, topo_file, config_file,
                              path_policy_file, is_sim=is_sim)
        """
        Initialize an instance of the class CoreBeaconServer.

        :param server_id: server identifier.
        :type server_id: int
        :param topo_file: topology file.
        :type topo_file: string
        :param config_file: configuration file.
        :type config_file: string
        :param path_policy_file: path policy file.
        :type path_policy_file: string
        :param is_sim: running on simulator
        :type is_sim: bool
        """
        # Sanity check that we should indeed be a core beacon server.
        assert self.topology.is_core_ad, "This shouldn't be a core BS!"
        self.beacons = defaultdict(self._ps_factory)
        self.core_segments = defaultdict(self._ps_factory)

    def _ps_factory(self):
        """

        :returns:
        :rtype:
        """
        return PathStore(self.path_policy)

    def propagate_core_pcb(self, pcb):
        """
        Propagates the core beacons to other core ADs.

        :returns:
        :rtype:
        """
        assert isinstance(pcb, PathSegment)
        ingress_if = pcb.if_id
        count = 0
        for core_router in self.topology.routing_edge_routers:
            skip = False
            for ad in pcb.ads:
                if (ad.pcbm.isd_id == core_router.interface.neighbor_isd and
                        ad.pcbm.ad_id == core_router.interface.neighbor_ad):
                    # Don't propagate a Core PCB back to an AD we know has
                    # already seen it.
                    skip = True
                    break
            if skip:
                continue
            new_pcb = copy.deepcopy(pcb)
            egress_if = core_router.interface.if_id
            last_pcbm = new_pcb.get_last_pcbm()
            if last_pcbm:
                ad_marking = self._create_ad_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp(),
                                                     last_pcbm.hof)
            else:
                ad_marking = self._create_ad_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp())

            new_pcb.add_ad(ad_marking)
            self._sign_beacon(new_pcb)
            dst = SCIONAddr.from_values(self.topology.isd_id,
                                        self.topology.ad_id, core_router.addr)
            beacon = PathConstructionBeacon.from_values(self.addr.get_isd_ad(),
                                                        dst, new_pcb)
            self.send(beacon, core_router.addr)
            count += 1
        return count

    def handle_pcbs_propagation(self):
        """
        Generate a new beacon or gets ready to forward the one received.
        """
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
        core_count = self.propagate_core_pcb(core_pcb)
        # Propagate received beacons. A core beacon server can only receive
        # beacons from other core beacon servers.
        beacons = []
        for ps in self.beacons.values():
            beacons.extend(ps.get_best_segments())
        for pcb in beacons:
            core_count += self.propagate_core_pcb(pcb)
        if core_count:
            logging.info("Propagated %d Core PCBs", core_count)

    def register_segments(self):
        """

        """
        self.register_core_segments()

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
            ps_addr = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError:
            # If there are no local path servers, stop here.
            return
        dst = SCIONAddr.from_values(
            self.topology.isd_id, self.topology.ad_id, ps_addr)
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, None,
                                         self.addr.get_isd_ad(), dst)
        self.send(pkt, dst.host_addr)

    def process_pcbs(self, pcbs):
        """
        Process new beacons and appends them to beacon list.
        """
        count = 0
        for raw_pcb in pcbs:
            pcb = PathSegment(raw_pcb)
            # Before we append the PCB for further processing we need to check
            # that it hasn't been received before.
            for ad in pcb.ads:
                if (ad.pcbm.isd_id == self.topology.isd_id and
                        ad.pcbm.ad_id == self.topology.ad_id):
                    count += 1
                    break
            else:
                self._try_to_verify_beacon(pcb)
        if count:
            logging.debug("Dropped %d previously seen Core Segment PCBs", count)

    def _check_certs_trc(self, isd_id, ad_id, cert_ver, trc_ver, if_id):
        """
        Return True or False whether the necessary TRC file is found.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param cert_ver: certificate chain file version.
        :type cert_ver: int
        :param trc_ver: TRC file version.
        :type trc_ver: int
        :param if_id: interface identifier.
        :type if_id: int

        :returns: True if the files exist, False otherwise.
        :rtype: bool
        """
        if self._get_trc(isd_id, trc_ver, if_id):
            return True
        else:
            return False

    def process_cert_chain_rep(self, cert_chain_rep):
        raise NotImplementedError

    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.

        :param pcb: verified path segment.
        :type pcb: PathSegment
        """
        isd_id = pcb.get_first_pcbm().isd_id
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
            pcb = self._terminate_pcb(pcb)
            assert pcb.segment_id != 32 * b"\x00", \
                "Trying to register a segment with ID 0:\n%s" % pcb
            # TODO(psz): sign here? discuss
            self.register_core_segment(pcb)
            count += 1
        logging.info("Registered %d Core paths", count)

    def _remove_revoked_pcbs(self, rev_info, if_id):
        candidates = []
        to_remove = []
        processed = set()
        for ps in self.core_segments.values():
            candidates += ps.candidates
        for cand in candidates:
            if cand.id in processed:
                continue
            processed.add(cand.id)
            # If the beacon was received on this interface, remove it from
            # the store. We also check, if the interface didn't come up in
            # the mean time. Caveat: There is a small chance that a valid
            # beacon gets removed, in case a new beacon reaches the BS through
            # the interface, which is getting revoked, before the keep-alive
            # message updates the interface state to 'ACTIVE'. However,
            # worst, the valid beacon would get added within the next
            # propagation period.
            if self.ifid_state[if_id].is_expired() and cand.pcb.if_id == if_id:
                to_remove.append(cand.id)

        # Remove the affected segments from the path stores.
        for ps in self.core_segments.values():
            ps.remove_segments(to_remove)


class LocalBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a non-core AD.

    Receives, processes, and propagates beacons received by other beacon
    servers.
    """

    def __init__(self, server_id, topo_file, config_file, path_policy_file,
                 is_sim=False):
        """
        Initialize an instance of the class LocalBeaconServer.

        :param server_id: server identifier.
        :type server_id: int
        :param topo_file: topology file.
        :type topo_file: string
        :param config_file: configuration file.
        :type config_file: string
        :param path_policy_file: path policy file.
        :type path_policy_file: string
        :param is_sim: running on simulator
        :type is_sim: bool
        """
        BeaconServer.__init__(self, server_id, topo_file, config_file,
                              path_policy_file, is_sim=is_sim)
        # Sanity check that we should indeed be a local beacon server.
        assert not self.topology.is_core_ad, "This shouldn't be a local BS!"
        self.beacons = PathStore(self.path_policy)
        self.up_segments = PathStore(self.path_policy)
        self.down_segments = PathStore(self.path_policy)
        self.cert_chain_requests = {}
        self.cert_chains = {}
        cert_chain_file = get_cert_chain_file_path(
            self.topology.isd_id, self.topology.ad_id, self.topology.isd_id,
            self.topology.ad_id, self.config.cert_ver)
        self.cert_chain = CertificateChain(cert_chain_file)

    def _check_certs_trc(self, isd_id, ad_id, cert_ver, trc_ver, if_id):
        """
        Return True or False whether the necessary Certificate and TRC files are
        found.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param cert_ver: certificate chain file version.
        :type cert_ver: int
        :param trc_ver: TRC file version.
        :type trc_ver: int
        :param if_id: interface identifier.
        :type if_id: int

        :returns: True if the files exist, False otherwise.
        :rtype: bool
        """
        trc = self._get_trc(isd_id, trc_ver, if_id)
        if trc:
            cert_chain = self.cert_chains.get((isd_id, ad_id, cert_ver))
            if not cert_chain:
                # Try loading file from disk
                cert_chain_file = get_cert_chain_file_path(
                    self.topology.isd_id, self.topology.ad_id,
                    isd_id, ad_id, cert_ver)
                if os.path.exists(cert_chain_file):
                    cert_chain = CertificateChain(cert_chain_file)
                    self.cert_chains[(isd_id, ad_id, cert_ver)] = cert_chain
            if cert_chain or self.cert_chain.certs[0].issuer in trc.core_ads:
                return True
            else:
                # Requesting certificate chain file from cert server
                cert_chain_tuple = (isd_id, ad_id, cert_ver)
                now = int(SCIONTime.get_time())
                if (cert_chain_tuple not in self.cert_chain_requests or
                    (now - self.cert_chain_requests[cert_chain_tuple] >
                        BeaconServer.REQUESTS_TIMEOUT)):
                    new_cert_chain_req = \
                        CertChainRequest.from_values(
                            PT.CERT_CHAIN_REQ_LOCAL,
                            self.addr, if_id, self.topology.isd_id,
                            self.topology.ad_id, isd_id, ad_id, cert_ver)
                    try:
                        dst_addr = self.dns_query_topo(CERTIFICATE_SERVICE)[0]
                    except SCIONServiceLookupError as e:
                        logging.warning("Unable to send cert query: %s", e)
                        return False
                    self.send(new_cert_chain_req, dst_addr)
                    self.cert_chain_requests[cert_chain_tuple] = now
                    return False
        else:
            return False

    def register_up_segment(self, pcb):
        """
        Send up-segment to Local Path Servers

        :raises:
            SCIONServiceLookupError: path server lookup failure
        """
        info = PathSegmentInfo.from_values(
            PST.UP, self.topology.isd_id, self.topology.isd_id,
            pcb.get_first_pcbm().ad_id, self.topology.ad_id)
        ps_addr = self.dns_query_topo(PATH_SERVICE)[0]
        records = PathSegmentRecords.from_values(info, [pcb])
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, None,
                                         self.addr, self.addr.get_isd_ad())
        self.send(pkt, ps_addr)

    def register_down_segment(self, pcb):
        """
        Send down-segment to Core Path Server
        """
        info = PathSegmentInfo.from_values(
            PST.DOWN, self.topology.isd_id, self.topology.isd_id,
            pcb.get_first_pcbm().ad_id, self.topology.ad_id)
        core_path = pcb.get_path(reverse_direction=True)
        records = PathSegmentRecords.from_values(info, [pcb])
        dst_isd_ad = ISD_AD(pcb.get_isd(), pcb.get_first_pcbm().ad_id)
        pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, core_path,
                                         self.addr, dst_isd_ad)
        next_hop = self.ifid2addr[core_path.get_fwd_if()]
        self.send(pkt, next_hop)

    def register_segments(self):
        """
        Register paths according to the received beacons.
        """
        self.register_up_segments()
        self.register_down_segments()

    def process_pcbs(self, pcbs):
        """
        Process new beacons and appends them to beacon list.
        """
        for raw_pcb in pcbs:
            pcb = PathSegment(raw_pcb)
            if self.path_policy.check_filters(pcb):
                self._try_to_verify_beacon(pcb)

    def process_cert_chain_rep(self, cert_chain_rep):
        """
        Process the Certificate chain reply.

        :param cert_chain_rep: certificate chain reply.
        :type cert_chain_rep: CertChainReply
        """
        assert isinstance(cert_chain_rep, CertChainReply)
        logging.info("Certificate chain reply received.")
        cert_chain_file = get_cert_chain_file_path(
            self.topology.isd_id, self.topology.ad_id,
            cert_chain_rep.isd_id, cert_chain_rep.ad_id,
            cert_chain_rep.version)
        write_file(cert_chain_file, cert_chain_rep.cert_chain.decode('utf-8'))
        self.cert_chains[
            (cert_chain_rep.isd_id,
             cert_chain_rep.ad_id,
             cert_chain_rep.version)] = CertificateChain(cert_chain_file)
        if (cert_chain_rep.isd_id, cert_chain_rep.ad_id,
                cert_chain_rep.version) in self.cert_chain_requests:
            del self.cert_chain_requests[(cert_chain_rep.isd_id,
                                          cert_chain_rep.ad_id,
                                          cert_chain_rep.version)]
        self.handle_unverified_beacons()

    def _remove_revoked_pcbs(self, rev_info, if_id):
        candidates = (self.down_segments.candidates +
                      self.up_segments.candidates)
        to_remove = []
        processed = set()
        for cand in candidates:
            if cand.id in processed:
                continue
            processed.add(cand.id)
            # If the beacon was received on this interface, remove it from
            # the store. We also check, if the interface didn't come up in
            # the mean time. Caveat: There is a small chance that a valid
            # beacon gets removed, in case a new beacon reaches the BS through
            # the interface, which is getting revoked, before the keep-alive
            # message updates the interface state to 'ACTIVE'. However,
            # worst, the valid beacon would get added within the next
            # propagation period.
            if self.ifid_state[if_id].is_expired() and cand.pcb.if_id == if_id:
                to_remove.append(cand.id)

        # Remove the affected segments from the path stores.
        self.up_segments.remove_segments(to_remove)
        self.down_segments.remove_segments(to_remove)

    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.
        """
        self.beacons.add_segment(pcb)
        self.up_segments.add_segment(pcb)
        self.down_segments.add_segment(pcb)

    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        # TODO: define function that dispatches the pcbs among the interfaces
        best_segments = self.beacons.get_best_segments()
        for pcb in best_segments:
            self.propagate_downstream_pcb(pcb)

    def register_up_segments(self):
        """
        Register the paths to the core.
        """
        best_segments = self.up_segments.get_best_segments()
        for pcb in best_segments:
            pcb = self._terminate_pcb(pcb)
            pcb.remove_signatures()
            # TODO(psz): sign here? discuss
            try:
                self.register_up_segment(pcb)
            except SCIONServiceLookupError as e:
                logging.warning("Unable to send up path registration: %s", e)
                continue
            logging.info("Up path registered: %s", pcb.segment_id)

    def register_down_segments(self):
        """
        Register the paths from the core.
        """
        best_segments = self.down_segments.get_best_segments()
        for pcb in best_segments:
            pcb = self._terminate_pcb(pcb)
            pcb.remove_signatures()
            # TODO(psz): sign here? discuss
            self.register_down_segment(pcb)
            logging.info("Down path registered: %s", pcb.segment_id)


def main():
    """
    Main function.
    """
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('type', choices=['core', 'local'],
                        help='Core or local path server')
    parser.add_argument('server_id', help='Server identifier')
    parser.add_argument('topo_file', help='Topology file')
    parser.add_argument('conf_file', help='AD configuration file')
    parser.add_argument('path_policy_file', help='AD path policy file')
    parser.add_argument('log_file', help='Log file')
    args = parser.parse_args()
    init_logging(args.log_file)

    if args.type == "core":
        beacon_server = CoreBeaconServer(args.server_id, args.topo_file,
                                         args.conf_file, args.path_policy_file)
    else:
        beacon_server = LocalBeaconServer(args.server_id, args.topo_file,
                                          args.conf_file,
                                          args.path_policy_file)

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
