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
:mod:`base` --- Base beacon server
==================================
"""
# Stdlib
import base64
import copy
import logging
import os
import threading
from _collections import deque
from abc import ABCMeta, abstractmethod

# External packages
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

# SCION
from infrastructure.scion_elem import SCIONElement
from infrastructure.beacon_server.if_state import InterfaceState
from infrastructure.beacon_server.rev_obj import RevocationObject
from lib.crypto.asymcrypto import sign
from lib.crypto.certificate import CertificateChain, verify_sig_chain_trc
from lib.crypto.hash_chain import HashChain, HashChainExhausted
from lib.crypto.symcrypto import gen_of_mac
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
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
from lib.packet.cert_mgmt import TRCRequest
from lib.packet.opaque_field import HopOpaqueField
from lib.packet.path_mgmt import (
    IFStateInfo,
    IFStatePayload,
    IFStateRequest,
    RevocationInfo,
)
from lib.packet.pcb import (
    ASMarking,
    PCBMarking,
    PathSegment,
)
from lib.packet.pcb_ext import BeaconExtType
from lib.packet.pcb_ext.mtu import MtuPcbExt
from lib.packet.pcb_ext.rev import RevPcbExt
from lib.packet.pcb_ext.sibra import SibraPcbExt
from lib.packet.scion import PacketType as PT
from lib.path_store import PathPolicy
from lib.thread import thread_safety_net
from lib.types import (
    CertMgmtType,
    IFIDType,
    OpaqueFieldType as OFT,
    PCBType,
    PathMgmtType as PMT,
    PayloadClass,
)
from lib.util import (
    SCIONTime,
    get_sig_key_file_path,
    read_file,
    sleep_interval,
)
from lib.zookeeper import ZkNoConnection, ZkSharedCache, Zookeeper
from external.expiring_dict import ExpiringDict


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
        self.of_gen_key = PBKDF2(self.config.master_as_key, b"Derive OF Key")
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
                                    str(self.addr.host)])
            self.zk = Zookeeper(self.addr.isd_as, BEACON_SERVICE, name_addrs,
                                self.topology.zookeepers)
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
        seed = self.config.master_as_key + bytes([if_id])
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
                as_marking = self._create_as_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp(),
                                                     last_pcbm.hof)
            else:
                as_marking = self._create_as_marking(ingress_if, egress_if,
                                                     new_pcb.get_timestamp())

            new_pcb.add_as(as_marking)
            self._sign_beacon(new_pcb)
            beacon = self._build_packet(
                PT.BEACON, dst_ia=router_child.interface.isd_as,
                payload=new_pcb)
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
        for asm in pcb.ases:
            for ext in asm.ext:
                if ext.EXT_TYPE == MtuPcbExt.EXT_TYPE:
                    self.mtu_ext_handler(ext, asm)
                elif ext.EXT_TYPE == RevPcbExt.EXT_TYPE:
                    self.rev_ext_handler(ext, asm)
                elif ext.EXT_TYPE == SibraPcbExt.EXT_TYPE:
                    self.sibra_ext_handler(ext, asm)
                else:
                    logging.warning("PCB extension %s(%s) not supported" % (
                        BeaconExtType.to_str(ext.EXT_TYPE), ext.EXT_TYPE))

    def mtu_ext_handler(self, ext, asm):
        """
        Dummy handler for MtuPcbExt.
        """
        logging.info("MTU %s: %s" % (asm.pcbm.isd_as, ext))

    def rev_ext_handler(self, ext, asm):
        """
        Handler for RevPcbExt.
        """
        logging.info("REV %s: %s" % (asm.pcbm.isd_as, ext))
        rev_info = ext.rev_info
        # Trigger the removal of PCBs which contain the revoked interface
        self._remove_revoked_pcbs(rev_info=rev_info, if_id=None)
        # Inform the local PS
        self._send_rev_to_local_ps(rev_info=rev_info)

    def sibra_ext_handler(self, ext, asm):
        """
        Dummy handler for SibraPcbExt.
        """
        logging.info("Sibra %s: %s" % (asm.pcbm.isd_as, ext))

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

    def _create_as_marking(self, ingress_if, egress_if, ts, prev_hof=None):
        """
        Creates an AS Marking for given ingress and egress interfaces,
        timestamp, and previous HOF.

        :param int ingress_if: ingress interface.
        :param int egress_if: egress interface.
        """
        hof = HopOpaqueField.from_values(self.HOF_EXP_TIME,
                                         ingress_if, egress_if)
        if prev_hof is None:
            hof.info = OFT.XOVR_POINT
        hof.mac = gen_of_mac(self.of_gen_key, hof, prev_hof, ts)
        pcbm = PCBMarking.from_values(
            self.addr.isd_as, hof, self._get_if_rev_token(ingress_if))
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
                PCBMarking.from_values(router_peer.interface.isd_as,
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
        return ASMarking.from_values(pcbm, peer_markings,
                                     self._get_if_rev_token(egress_if),
                                     ext=extensions)

    def _terminate_pcb(self, pcb):
        """
        Copies a PCB, terminates it and adds the segment ID.

        Terminating a PCB means adding a opaque field with the egress IF set
        to 0, i.e., there is no AS to forward a packet containing this path
        segment to.

        :param pcb: The PCB to terminate.
        :type pcb: PathSegment

        :returns: Terminated PCB
        :rtype: PathSegment
        """
        pcb = copy.deepcopy(pcb)
        last_hop = self._create_as_marking(
            pcb.if_id, 0, pcb.get_timestamp(), pcb.get_last_pcbm().hof)
        pcb.add_as(last_hop)
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
                                                     chain.current_element())
                payload = IFStatePayload.from_values([state_info])
                payload.pack()
                mgmt_packet = self._build_packet(payload=payload)
                for er in self.topology.get_all_edge_routers():
                    if er.interface.if_id != ifid:
                        mgmt_packet.addrs.dst.host = er.addr
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
        if self._check_certs_trc(
                last_pcbm.isd_as, pcb.get_last_asm().cert_ver, pcb.trc_ver):
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
    def _check_certs_trc(self, isd_as, cert_ver, trc_ver):
        """
        Return True or False whether the necessary Certificate and TRC files are
        found.

        :param ISD_AS isd_is: ISD-AS identifier.
        :param int cert_ver: certificate chain file version.
        :param int trc_ver: TRC file version.
        """
        raise NotImplementedError

    def _get_trc(self, isd_as, trc_ver):
        """
        Get TRC from local storage or memory.

        :param ISD_AS isd_as: ISD-AS identifier.
        :param int trc_ver: TRC file version.
        """
        trc = self.trust_store.get_trc(isd_as[0], trc_ver)
        if not trc:
            # Requesting TRC file from cert server
            trc_tuple = isd_as[0], trc_ver
            now = int(SCIONTime.get_time())
            if (trc_tuple not in self.trc_requests or
                (now - self.trc_requests[trc_tuple] >
                    self.REQUESTS_TIMEOUT)):
                trc_req = TRCRequest.from_values(isd_as, trc_ver)
                logging.info("Requesting %sv%s TRC", isd_as[0], trc_ver)
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
        cert_ia = pcb.get_last_pcbm().isd_as
        cert_ver = pcb.get_last_asm().cert_ver
        chain = self.trust_store.get_cert(cert_ia, cert_ver)
        if not chain:  # Signed by root. TODO(PSz): has to be revised
            chain = CertificateChain.from_values([])
        trc = self.trust_store.get_trc(cert_ia[0], pcb.trc_ver)

        new_pcb = copy.deepcopy(pcb)
        new_pcb.if_id = 0
        new_pcb.ases[-1].sig = b''
        return verify_sig_chain_trc(new_pcb.pack(), pcb.ases[-1].sig,
                                    str(cert_ia), chain, trc, pcb.trc_ver)

    def _sign_beacon(self, pcb):
        """
        Sign a beacon. Signature is appended to the last ASMarking.

        :param pcb: beacon to sign.
        :type pcb: PathSegment
        """
        # if_id field is excluded from signature as it is changed by ingress ERs
        if pcb.ases[-1].sig:
            logging.warning("PCB already signed.")
            return
        (pcb.if_id, tmp_if_id) = (0, pcb.if_id)
        signature = sign(pcb.pack(), self.signing_key)
        pcb.ases[-1].sig = signature
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
            state_pkt.addrs.dst.host = er.addr
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
            else:  # if_id = None means that this is an AS in downstream
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
                          "interface %s.", mgmt_pkt.addrs.src, request.if_id)
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
        state_pkt = self._build_packet(mgmt_pkt.addrs.src.host, payload=payload)
        self.send(state_pkt, mgmt_pkt.addrs.src.host)
