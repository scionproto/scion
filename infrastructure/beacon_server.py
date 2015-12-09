#!/usr/bin/python3
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
import base64
import copy
import logging
import os
import struct
import threading
from _collections import defaultdict, deque
from abc import ABCMeta, abstractmethod

# External packages
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.asymcrypto import sign
from lib.crypto.certificate import CertificateChain, verify_sig_chain_trc
from lib.crypto.hash_chain import HashChain, HashChainExhausted
from lib.crypto.symcrypto import gen_of_mac
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    IFID_PKT_TOUT,
    PATH_POLICY_FILE,
    PATH_SERVICE,
    SCION_UDP_PORT,
)
from lib.errors import (
    SCIONIndexError,
    SCIONKeyError,
    SCIONParseError,
    SCIONServiceLookupError,
)
from lib.main import main_default, main_wrapper
from lib.packet.cert_mgmt import (
    CertChainRequest,
    TRCRequest,
)
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
)
from lib.packet.path_mgmt import (
    IFStateInfo,
    IFStatePayload,
    IFStateRequest,
    PathSegmentInfo,
    PathRecordsReg,
    RevocationInfo,
)
from lib.packet.pcb import (
    ADMarking,
    PCBMarking,
    PathSegment,
)
from lib.packet.pcb_ext import BeaconExtType
from lib.packet.pcb_ext.mtu import MtuPcbExt
from lib.packet.pcb_ext.rev import RevPcbExt
from lib.packet.pcb_ext.sibra import SibraPcbExt
from lib.packet.scion import PacketType as PT
from lib.path_store import PathPolicy, PathStore
from lib.thread import thread_safety_net
from lib.types import (
    CertMgmtType,
    IFIDType,
    OpaqueFieldType as OFT,
    PCBType,
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
)
from lib.util import (
    Raw,
    SCIONTime,
    get_sig_key_file_path,
    read_file,
    sleep_interval,
)
from lib.zookeeper import ZkNoConnection, ZkSharedCache, Zookeeper
from external.expiring_dict import ExpiringDict


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

    def reset(self):
        """
        Resets the state of an InterfaceState object.
        """
        with self._lock:
            self.active_since = 0
            self.last_updated = 0
            self._state = self.INACTIVE

    def revoke_if_expired(self):
        """
        Sets the state of the interface to revoked.
        """
        with self._lock:
            if self._state == self.TIMED_OUT:
                self._state = self.REVOKED

    def is_inactive(self):
        return self._state == self.INACTIVE

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
        if2rev_tokens: Contains the currently used revocation token
            hash-chain for each interface.
    """
    SERVICE_TYPE = BEACON_SERVICE
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
    # Number of tokens the BS checks when receiving a revocation.
    N_TOKENS_CHECK = 20

    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        # TODO: add 2 policies
        self.path_policy = PathPolicy.from_file(
            os.path.join(conf_dir, PATH_POLICY_FILE))
        self.unverified_beacons = deque()
        self.trc_requests = {}
        self.trcs = {}
        sig_key_file = get_sig_key_file_path(self.conf_dir)
        self.signing_key = base64.b64decode(read_file(sig_key_file))
        self.of_gen_key = PBKDF2(self.config.master_ad_key, b"Derive OF Key")
        logging.info(self.config.__dict__)
        self.if2rev_tokens = {}
        self._if_rev_token_lock = threading.Lock()
        self.revs_to_downstream = ExpiringDict(max_len=1000, max_age_seconds=60)

        self.ifid_state = {}
        for ifid in self.ifid2addr:
            self.ifid_state[ifid] = InterfaceState()

        self.PLD_CLASS_MAP = {
            PayloadClass.PCB: {PCBType.SEGMENT: self.handle_pcb},
            PayloadClass.IFID: {IFIDType.PAYLOAD: self.handle_ifid_packet},
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_rep,
                CertMgmtType.TRC_REPLY: self.process_trc_rep,
            },
            PayloadClass.PATH: {PMT.IFSTATE_REQ: self._handle_ifstate_request},
        }

        if not is_sim:
            # Add more IPs here if we support dual-stack
            name_addrs = "\0".join([self.id, str(SCION_UDP_PORT),
                                    str(self.addr.host_addr)])
            self.zk = Zookeeper(
                self.topology.isd_id, self.topology.ad_id, BEACON_SERVICE,
                name_addrs, self.topology.zookeepers)
            self.zk.retry("Joining party", self.zk.party_setup)
            self.incoming_pcbs = deque()
            self.pcb_cache = ZkSharedCache(
                self.zk, self.ZK_PCB_CACHE_PATH, self.process_pcbs)
            self.revobjs_cache = ZkSharedCache(
                self.zk, self.ZK_REVOCATIONS_PATH, self.process_rev_objects)

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
        with self._if_rev_token_lock:
            ret = None
            if if_id == 0:
                ret = bytes(32)
            else:
                chain = self._get_if_hash_chain(if_id)
                if chain:
                    ret = chain.current_element()
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
            beacon = self._build_packet(
                PT.BEACON, dst_isd=router_child.interface.neighbor_isd,
                dst_ad=router_child.interface.neighbor_ad, payload=new_pcb)
            self.send(beacon, router_child.addr)
            logging.info("Downstream PCB propagated!")

    @abstractmethod
    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        raise NotImplementedError

    def handle_pcb(self, pkt):
        """
        Receives beacon and stores it for processing.

        :param pcb: path construction beacon.
        :type pcb: PathConstructionBeacon
        """
        pcb = pkt.get_payload()
        if not self.path_policy.check_filters(pcb):
            return
        self.incoming_pcbs.append(pcb)
        entry_name = "%s-%s" % (pcb.get_hops_hash(hex=True),
                                SCIONTime.get_time())
        try:
            self.pcb_cache.store(entry_name, pcb.pack())
        except ZkNoConnection:
            logging.error("Unable to store PCB in shared cache: "
                          "no connection to ZK")

    def handle_ext(self, pcb):
        """
        Handle beacon extensions.
        """
        for ad in pcb.ads:
            for ext in ad.ext:
                if ext.EXT_TYPE == MtuPcbExt.EXT_TYPE:
                    self.mtu_ext_handler(ext, ad)
                elif ext.EXT_TYPE == RevPcbExt.EXT_TYPE:
                    self.rev_ext_handler(ext, ad)
                elif ext.EXT_TYPE == SibraPcbExt.EXT_TYPE:
                    self.sibra_ext_handler(ext, ad)
                else:
                    logging.warning("PCB extension %s(%s) not supported" % (
                        BeaconExtType.to_str(ext.EXT_TYPE), ext.EXT_TYPE))

    def mtu_ext_handler(self, ext, ad):
        """
        Dummy handler for MtuPcbExt.
        """
        logging.info("MTU (%d, %d): %s" % (ad.pcbm.ad_id, ad.pcbm.isd_id, ext))

    def rev_ext_handler(self, ext, ad):
        """
        Handler for RevPcbExt.
        """
        logging.info("REV (%d, %d): %s" % (ad.pcbm.ad_id, ad.pcbm.isd_id, ext))
        rev_info = ext.rev_info
        # Trigger the removal of PCBs which contain the revoked interface
        self._remove_revoked_pcbs(rev_info=rev_info, if_id=None)
        # Inform the local PS
        self._send_rev_to_local_ps(rev_info=rev_info)

    def sibra_ext_handler(self, ext, ad):
        """
        Dummy handler for SibraPcbExt.
        """
        logging.info("Sibra (%d, %d): %s" % (ad.pcbm.ad_id, ad.pcbm.isd_id,
                                             ext))

    @abstractmethod
    def process_pcbs(self, pcbs, raw=True):
        """
        Processes new beacons and appends them to beacon list.
        """
        raise NotImplementedError

    def process_pcb_queue(self):
        pcbs = []
        while self.incoming_pcbs:
            pcbs.append(self.incoming_pcbs.popleft())
        self.process_pcbs(pcbs, raw=False)
        logging.debug("Processed %d pcbs from incoming queue", len(pcbs))

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
        hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                         ingress_if, egress_if)
        if prev_hof is None:
            hof.info = OFT.XOVR_POINT
        hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
        pcbm = PCBMarking.from_values(self.topology.isd_id, self.topology.ad_id,
                                      hof, self._get_if_rev_token(ingress_if))
        peer_markings = []
        for router_peer in sorted(self.topology.peer_edge_routers):
            if_id = router_peer.interface.if_id
            if not self.ifid_state[if_id].is_active():
                logging.warning('Peer ifid:%d inactive (not added).', if_id)
                continue
            peer_hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                                  if_id, egress_if)
            peer_hof.info = OFT.XOVR_POINT
            peer_hof.mac = gen_of_mac(self.of_gen_key, peer_hof, hof, ts)
            peer_marking = \
                PCBMarking.from_values(router_peer.interface.neighbor_isd,
                                       router_peer.interface.neighbor_ad,
                                       peer_hof, self._get_if_rev_token(if_id))
            peer_markings.append(peer_marking)

        # Add extensions.
        extensions = []
        extensions.append(MtuPcbExt.from_values(self.config.mtu))
        # FIXME(kormat): add real values, based on the interface pair specified.
        extensions.append(SibraPcbExt.from_values(1, 2))
        for _, rev_info in self.revs_to_downstream.items():
            rev_ext = RevPcbExt.from_values(rev_info)
            extensions.append(rev_ext)
        return ADMarking.from_values(pcbm, peer_markings,
                                     self._get_if_rev_token(egress_if),
                                     ext=extensions)

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

        return pcb

    def handle_ifid_packet(self, pkt):
        """
        Update the interface state for the corresponding interface.

        :param ipkt: The IFIDPayload.
        :type ipkt: IFIDPayload
        """
        payload = pkt.get_payload()
        ifid = payload.reply_id
        if ifid not in self.ifid_state:
            raise SCIONKeyError("Invalid IF %d in IFIDPayload" % ifid)
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
                payload.pack()
                mgmt_packet = self._build_packet(payload=payload)
                for er in self.topology.get_all_edge_routers():
                    if er.interface.if_id != ifid:
                        mgmt_packet.addrs.dst_addr = er.addr
                        self.send(mgmt_packet, er.addr)

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
        was_master = False
        start = SCIONTime.get_time()
        while True:
            sleep_interval(start, worker_cycle, "BS.worker cycle")
            start = SCIONTime.get_time()
            try:
                self.process_pcb_queue()
                self.handle_unverified_beacons()
                self.zk.wait_connected()
                self.pcb_cache.process()
                self.revobjs_cache.process()
                if not self.zk.get_lock(lock_timeout=0, conn_timeout=0):
                    was_master = False
                    continue
                if not was_master:
                    self._became_master()
                    was_master = True
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
                try:
                    self.register_segments()
                except SCIONKeyError as e:
                    logging.error("Register_segments: %s", e)
                    pass
                last_registration = now

    def _became_master(self):
        """
        Called when a BS becomes the new master. Resets some state that will be
        rebuilt over time.
        """
        # Reset all timed-out and revoked interfaces to inactive.
        for (_, ifstate) in self.ifid_state.items():
            if not ifstate.is_active():
                ifstate.reset()

    def _try_to_verify_beacon(self, pcb, quiet=False):
        """
        Try to verify a beacon.

        :param pcb: path segment to verify.
        :type pcb: PathSegment
        """
        assert isinstance(pcb, PathSegment)
        last_pcbm = pcb.get_last_pcbm()
        if self._check_certs_trc(last_pcbm.isd_id, last_pcbm.ad_id,
                                 pcb.get_last_adm().cert_ver, pcb.trc_ver):
            if self._verify_beacon(pcb):
                self._handle_verified_beacon(pcb)
            else:
                logging.warning("Invalid beacon. %s", pcb)
        else:
            if not quiet:
                logging.warning("Certificate(s) or TRC missing for pcb: %s",
                                pcb.short_desc())
            self.unverified_beacons.append(pcb)

    @abstractmethod
    def _check_certs_trc(self, isd_id, ad_id, cert_ver, trc_ver):
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
        """
        raise NotImplementedError

    def _get_trc(self, isd_id, ad_id, trc_ver):
        """
        Get TRC from local storage or memory.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int
        :param trc_ver: TRC file version.
        :type trc_ver: int
        """
        trc = self.trust_store.get_trc(isd_id, trc_ver)
        if not trc:
            # Requesting TRC file from cert server
            trc_tuple = (isd_id, trc_ver)
            now = int(SCIONTime.get_time())
            if (trc_tuple not in self.trc_requests or
                (now - self.trc_requests[trc_tuple] >
                    self.REQUESTS_TIMEOUT)):
                trc_req = TRCRequest.from_values(isd_id, ad_id, trc_ver)
                logging.info("Requesting %sv%s TRC", isd_id, trc_ver)
                try:
                    dst_addr = self.dns_query_topo(CERTIFICATE_SERVICE)[0]
                except SCIONServiceLookupError as e:
                    logging.warning("Sending TRC request failed: %s", e)
                    return None
                req_pkt = self._build_packet(dst_addr, payload=trc_req)
                self.send(req_pkt, dst_addr)
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
        cert_isd = last_pcbm.isd_id
        cert_ad = last_pcbm.ad_id
        cert_ver = pcb.get_last_adm().cert_ver
        trc_ver = pcb.trc_ver
        subject = "%s-%s" % (cert_isd, cert_ad)
        chain = self.trust_store.get_cert(cert_isd, cert_ad, cert_ver)
        if not chain:  # Signed by root. TODO(PSz): has to be revised
            chain = CertificateChain.from_values([])
        trc = self.trust_store.get_trc(cert_isd, trc_ver)

        new_pcb = copy.deepcopy(pcb)
        new_pcb.if_id = 0
        new_pcb.ads[-1].sig = b''
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

    def process_trc_rep(self, pkt):
        """
        Process the TRC reply.

        :param trc_rep: TRC reply.
        :type trc_rep: TRCReply
        """
        rep = pkt.get_payload()
        logging.info("TRC reply received for %s", rep.trc.get_isd_ver())
        self.trust_store.add_trc(rep.trc)

        rep_key = rep.trc.get_isd_ver()
        if rep_key in self.trc_requests:
            del self.trc_requests[rep_key]

    def handle_unverified_beacons(self):
        """
        Handle beacons which are waiting to be verified.
        """
        for _ in range(len(self.unverified_beacons)):
            pcb = self.unverified_beacons.popleft()
            self._try_to_verify_beacon(pcb, quiet=True)

    def process_rev_objects(self, rev_objs):
        """
        Processes revocation objects stored in Zookeeper.
        """
        for raw_obj in rev_objs:
            try:
                rev_obj = RevocationObject(raw_obj)
            except SCIONParseError as e:
                logging.error("Error processing revocation object from ZK: %s",
                              e)
                continue
            chain = self._get_if_hash_chain(rev_obj.if_id)
            if not chain:
                logging.warning("Hash-Chain for IF %d doesn't exist.",
                                rev_obj.if_id)
                return
            if chain.current_index() > rev_obj.hash_chain_idx:
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
        entry_name = "%s:%s" % (chain.start_element(hex_=True),
                                chain.next_element(hex_=True))
        self.revobjs_cache.store(entry_name, rev_obj.pack())
        logging.info("Issuing revocation for IF %d.", if_id)
        # Issue revocation to all ERs.
        info = IFStateInfo.from_values(if_id, False, chain.next_element())
        payload = IFStatePayload.from_values([info])
        state_pkt = self._build_packet(payload=payload)
        for er in self.topology.get_all_edge_routers():
            state_pkt.addrs.dst_addr = er.addr
            self.send(state_pkt, er.addr)
        self._process_revocation(rev_info, if_id)

    def _send_rev_to_local_ps(self, rev_info):
        """
        Sends the given revocation to its local path server.
        :param rev_info: The RevocationInfo object
        :type rev_info: RevocationInfo
        """
        if self.zk.have_lock() and self.topology.path_servers:
            try:
                ps_addr = self.dns_query_topo(PATH_SERVICE)[0]
            except SCIONServiceLookupError:
                # If there are no local path servers, stop here.
                return
            pkt = self._build_packet(ps_addr, payload=rev_info)
            logging.info("Sending revocation to local PS.")
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
        self._send_rev_to_local_ps(rev_info)
        # Add the revocation to the downstream queue
        self.revs_to_downstream[rev_info.rev_token] = rev_info
        # Propagate the Revocation instantly
        self.handle_pcbs_propagation()

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

    def _pcb_list_to_remove(self, candidates, rev_info, if_id):
        """
        Calculates the list of PCBs to remove.
        Called by _remove_revoked_pcbs.

        :param candidates: Candidate PCBs.
        :type candidates: List
        :param rev_info: The RevocationInfo object.
        :type rev_info: RevocationInfo
        :param if_id: The if_id to be revoked
        :type if_id: int
        """
        to_remove = []
        processed = set()
        for cand in candidates:
            if cand.id in processed:
                continue
            processed.add(cand.id)
            if if_id is not None:
                # If the beacon was received on this interface, remove it from
                # the store. We also check, if the interface didn't come up in
                # the mean time. Caveat: There is a small chance that a valid
                # beacon gets removed, in case a new beacon reaches the BS
                # through the interface, which is getting revoked, before the
                # keep-alive message updates the interface state to 'ACTIVE'.
                # However, worst, the valid beacon would get added within the
                # next propagation period.
                if (self.ifid_state[if_id].is_expired() and
                        cand.pcb.if_id == if_id):
                    to_remove.append(cand.id)
            else:  # if_id = None means that this is an AD in downstream
                rtoken = rev_info.rev_token
                for iftoken in cand.pcb.get_all_iftokens():
                    if HashChain.verify(rtoken, iftoken, self.N_TOKENS_CHECK):
                        to_remove.append(cand.id)
        return to_remove

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
            ifid_states = self.ifid_state.items()
        elif request.if_id in self.ifid_state:
            ifid_states = [(request.if_id, self.ifid_state[request.if_id])]
        else:
            logging.error("Received ifstate request from %s for unknown "
                          "interface %s.", mgmt_pkt.addrs.get_src_addr(),
                          request.if_id)
            return

        for (ifid, state) in ifid_states:
            # Don't include inactive interfaces in response.
            if state.is_inactive():
                continue
            chain = self._get_if_hash_chain(ifid)
            info = IFStateInfo.from_values(ifid, state.is_active(),
                                           chain.next_element())
            infos.append(info)
        if not infos:
            logging.warning("No IF state info to put in response.")
            return

        payload = IFStatePayload.from_values(infos)
        state_pkt = self._build_packet(mgmt_pkt.addrs.src_addr, payload=payload)
        self.send(state_pkt, mgmt_pkt.addrs.src_addr)


class CoreBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a core AD.

    Starts broadcasting beacons down-stream within an ISD and across ISDs
    towards other core beacon servers.
    """
    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        # Sanity check that we should indeed be a core beacon server.
        assert self.topology.is_core_ad, "This shouldn't be a core BS!"
        self.core_beacons = defaultdict(self._ps_factory)

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
            beacon = self._build_packet(PT.BEACON, payload=new_pcb)
            self.send(beacon, core_router.addr)
            count += 1
        return count

    def handle_pcbs_propagation(self):
        """
        Generate a new beacon or gets ready to forward the one received.
        """
        timestamp = int(SCIONTime.get_time())
        # Create beacon for downstream ADs.
        down_iof = InfoOpaqueField.from_values(
            OFT.CORE, False, timestamp, self.topology.isd_id)
        downstream_pcb = PathSegment.from_values(down_iof)
        self.propagate_downstream_pcb(downstream_pcb)
        # Create beacon for core ADs.
        core_iof = InfoOpaqueField.from_values(
            OFT.CORE, False, timestamp, self.topology.isd_id)
        core_pcb = PathSegment.from_values(core_iof)
        core_count = self.propagate_core_pcb(core_pcb)
        # Propagate received beacons. A core beacon server can only receive
        # beacons from other core beacon servers.
        beacons = []
        for ps in self.core_beacons.values():
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
                                           pcb.get_first_pcbm().ad_id,
                                           self.topology.isd_id,
                                           self.topology.ad_id)
        pcb.remove_signatures()
        self._sign_beacon(pcb)
        # Register core path with local core path server.
        try:
            ps_addr = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError:
            # If there are no local path servers, stop here.
            return
        records = PathRecordsReg.from_values({info.seg_type: [pcb]})
        pkt = self._build_packet(ps_addr, payload=records)
        self.send(pkt, ps_addr)

    def process_pcbs(self, pcbs, raw=True):
        """
        Process new beacons and appends them to beacon list.
        """
        count = 0
        for pcb in pcbs:
            if raw:
                try:
                    pcb = PathSegment(pcb)
                except SCIONParseError as e:
                    logging.error("Unable to parse raw pcb: %s", e)
                    continue
            # Before we append the PCB for further processing we need to check
            # that it hasn't been received before.
            for ad in pcb.ads:
                if (ad.pcbm.isd_id == self.topology.isd_id and
                        ad.pcbm.ad_id == self.topology.ad_id):
                    count += 1
                    break
            else:
                self._try_to_verify_beacon(pcb)
                self.handle_ext(pcb)
        if count:
            logging.debug("Dropped %d previously seen Core Segment PCBs", count)

    def _check_certs_trc(self, isd_id, ad_id, cert_ver, trc_ver):
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

        :returns: True if the files exist, False otherwise.
        :rtype: bool
        """
        if self._get_trc(isd_id, ad_id, trc_ver):
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
        isd_id, ad_id = pcb.get_first_isd_ad()
        self.core_beacons[(isd_id, ad_id)].add_segment(pcb)

    def register_core_segments(self):
        """
        Register the core segment between core ADs.
        """
        core_segments = []
        for ps in self.core_beacons.values():
            core_segments.extend(ps.get_best_segments(sending=False))
        count = 0
        for pcb in core_segments:
            pcb = self._terminate_pcb(pcb)
            self._sign_beacon(pcb)
            self.register_core_segment(pcb)
            count += 1
        logging.info("Registered %d Core paths", count)

    def _remove_revoked_pcbs(self, rev_info, if_id):
        candidates = []
        for ps in self.core_beacons.values():
            candidates += ps.candidates
        to_remove = self._pcb_list_to_remove(candidates, rev_info, if_id)
        # Remove the affected segments from the path stores.
        for ps in self.core_beacons.values():
            ps.remove_segments(to_remove)


class LocalBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a non-core AD.

    Receives, processes, and propagates beacons received by other beacon
    servers.
    """

    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        # Sanity check that we should indeed be a local beacon server.
        assert not self.topology.is_core_ad, "This shouldn't be a local BS!"
        self.beacons = PathStore(self.path_policy)
        self.up_segments = PathStore(self.path_policy)
        self.down_segments = PathStore(self.path_policy)
        self.cert_chain_requests = {}
        self.cert_chains = {}
        self.cert_chain = self.trust_store.get_cert(self.topology.isd_id,
                                                    self.topology.ad_id)
        assert self.cert_chain

    def _check_certs_trc(self, isd_id, ad_id, cert_ver, trc_ver):
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

        :returns: True if the files exist, False otherwise.
        :rtype: bool
        """
        trc = self._get_trc(isd_id, ad_id, trc_ver)
        if trc:
            cert_chain = self.trust_store.get_cert(isd_id, ad_id, cert_ver)
            if cert_chain or self.cert_chain.certs[0].issuer in trc.core_ads:
                return True
            else:
                # Requesting certificate chain file from cert server
                cert_chain_tuple = (isd_id, ad_id, cert_ver)
                now = int(SCIONTime.get_time())
                if (cert_chain_tuple not in self.cert_chain_requests or
                    (now - self.cert_chain_requests[cert_chain_tuple] >
                        BeaconServer.REQUESTS_TIMEOUT)):
                    new_cert_chain_req = CertChainRequest.from_values(
                        isd_id, ad_id, cert_ver)
                    logging.info("Requesting %s certificate chain",
                                 new_cert_chain_req.short_desc())
                    try:
                        dst_addr = self.dns_query_topo(CERTIFICATE_SERVICE)[0]
                    except SCIONServiceLookupError as e:
                        logging.warning("Unable to send cert query: %s", e)
                        return False
                    req_pkt = self._build_packet(dst_addr,
                                                 payload=new_cert_chain_req)
                    self.send(req_pkt, dst_addr)
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
        ps_host = self.dns_query_topo(PATH_SERVICE)[0]
        records = PathRecordsReg.from_values({PST.UP: [pcb]})
        pkt = self._build_packet(ps_host, payload=records)
        self.send(pkt, ps_host)

    def register_down_segment(self, pcb):
        """
        Send down-segment to Core Path Server
        """
        core_path = pcb.get_path(reverse_direction=True)
        records = PathRecordsReg.from_values({PST.DOWN: [pcb]})
        pkt = self._build_packet(
            PT.PATH_MGMT, dst_isd=pcb.get_isd(),
            dst_ad=pcb.get_first_pcbm().ad_id, path=core_path, payload=records)
        fwd_if = core_path.get_fwd_if()
        if fwd_if not in self.ifid2addr:
            raise SCIONKeyError(
                "Invalid IF %d in CorePath" % fwd_if)

        next_hop = self.ifid2addr[fwd_if]
        self.send(pkt, next_hop)

    def register_segments(self):
        """
        Register paths according to the received beacons.
        """
        self.register_up_segments()
        self.register_down_segments()

    def process_pcbs(self, pcbs, raw=True):
        """
        Process new beacons and appends them to beacon list.
        """
        for pcb in pcbs:
            if raw:
                try:
                    pcb = PathSegment(pcb)
                except SCIONParseError as e:
                    logging.error("Unable to parse raw pcb: %s", e)
                    continue
            if self.path_policy.check_filters(pcb):
                self._try_to_verify_beacon(pcb)
                self.handle_ext(pcb)

    def process_cert_chain_rep(self, pkt):
        """
        Process the Certificate chain reply.

        :param cert_chain_rep: certificate chain reply.
        :type cert_chain_rep: CertChainReply
        """
        rep = pkt.get_payload()
        logging.info("Certificate chain reply received for %s",
                     rep.short_desc())
        rep_key = rep.cert_chain.get_leaf_isd_ad_ver()
        self.trust_store.add_cert(rep.cert_chain)
        if rep_key in self.cert_chain_requests:
            del self.cert_chain_requests[rep_key]

    def _remove_revoked_pcbs(self, rev_info, if_id):
        candidates = (self.down_segments.candidates +
                      self.up_segments.candidates)
        to_remove = self._pcb_list_to_remove(candidates, rev_info, if_id)
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
        best_segments = self.up_segments.get_best_segments(sending=False)
        for pcb in best_segments:
            pcb = self._terminate_pcb(pcb)
            pcb.remove_signatures()
            self._sign_beacon(pcb)
            try:
                self.register_up_segment(pcb)
            except SCIONServiceLookupError as e:
                logging.warning("Unable to send up path registration: %s", e)
                continue
            logging.info("Up path registered: %s", pcb.short_desc())

    def register_down_segments(self):
        """
        Register the paths from the core.
        """
        best_segments = self.down_segments.get_best_segments(sending=False)
        for pcb in best_segments:
            pcb = self._terminate_pcb(pcb)
            pcb.remove_signatures()
            self._sign_beacon(pcb)
            self.register_down_segment(pcb)
            logging.info("Down path registered: %s", pcb.short_desc())


if __name__ == "__main__":
    main_wrapper(main_default, CoreBeaconServer, LocalBeaconServer)
