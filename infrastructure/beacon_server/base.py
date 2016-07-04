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
import logging
import os
import threading
import time
from _collections import deque
from abc import ABCMeta, abstractmethod

# External packages
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

# SCION
from infrastructure.scion_elem import SCIONElement
from infrastructure.beacon_server.if_state import InterfaceState
from infrastructure.beacon_server.rev_obj import RevocationObject
from lib.crypto.certificate import verify_sig_chain_trc
from lib.crypto.hash_chain import HashChain, HashChainExhausted
from lib.defines import (
    BEACON_SERVICE,
    CERTIFICATE_SERVICE,
    PATH_POLICY_FILE,
    PATH_SERVICE,
    SCION_UDP_EH_DATA_PORT,
)
from lib.errors import (
    SCIONIndexError,
    SCIONKeyError,
    SCIONParseError,
    SCIONServiceLookupError,
)
from lib.packet.cert_mgmt import TRCRequest
from lib.packet.opaque_field import HopOpaqueField
from lib.packet.path_mgmt.ifstate import (
    IFStateInfo,
    IFStatePayload,
    IFStateRequest,
)
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.pcb import (
    ASMarking,
    PCBMarking,
    PathSegment,
)
from lib.packet.scion import SVCType
from lib.packet.scion_addr import ISD_AS
from lib.path_store import PathPolicy
from lib.thread import thread_safety_net
from lib.types import (
    CertMgmtType,
    IFIDType,
    PCBType,
    PathMgmtType as PMT,
    PayloadClass,
)
from lib.util import (
    get_sig_key_file_path,
    read_file,
    sleep_interval,
)
from lib.zk.cache import ZkSharedCache
from lib.zk.errors import ZkNoConnection
from lib.zk.zk import Zookeeper
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

    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
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
        for ifid in self.ifid2er:
            self.ifid_state[ifid] = InterfaceState()

        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.PCB: {PCBType.SEGMENT: self.handle_pcb},
            PayloadClass.IFID: {IFIDType.PAYLOAD: self.handle_ifid_packet},
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_rep,
                CertMgmtType.TRC_REPLY: self.process_trc_rep,
            },
            PayloadClass.PATH: {PMT.IFSTATE_REQ: self._handle_ifstate_request},
        }

        # FIXME(kormat): Add more IPs here when we support dual-stack
        name_addrs = "\0".join([self.id, str(self._port), str(self.addr.host)])
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
        for r in self.topology.child_edge_routers:
            beacon = self._mk_prop_beacon(pcb.copy(), r.interface.isd_as,
                                          r.interface.if_id)
            self.send(beacon, r.addr, r.port)
            logging.info("Downstream PCB propagated!")

    def _mk_prop_beacon(self, pcb, dst_ia, egress_if):
        ts = pcb.get_timestamp()
        asm = self._create_asm(pcb.p.ifID, egress_if, ts, pcb.last_hof())
        pcb.add_asm(asm)
        pcb.sign(self.signing_key)
        return self._build_packet(SVCType.BS, dst_ia=dst_ia, payload=pcb)

    def _mk_if_info(self, if_id):
        """
        Small helper method to make it easier to deal with ingress/egress
        interface being 0 while building ASMarkings.
        """
        d = {"remote_ia": ISD_AS.from_values(0, 0), "remote_if": 0, "mtu": 0}
        if not if_id:
            return d
        er = self.ifid2er[if_id]
        d["remote_ia"] = er.interface.isd_as
        d["remote_if"] = er.interface.if_id
        d["mtu"] = er.interface.mtu
        return d

    @abstractmethod
    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        raise NotImplementedError

    def handle_pcb(self, pkt):
        """Receives beacon and stores it for processing."""
        pcb = pkt.get_payload()
        if not self.path_policy.check_filters(pcb):
            return
        self.incoming_pcbs.append(pcb)
        entry_name = "%s-%s" % (pcb.get_hops_hash(hex=True), time.time())
        try:
            self.pcb_cache.store(entry_name, pcb.copy().pack())
        except ZkNoConnection:
            logging.error("Unable to store PCB in shared cache: "
                          "no connection to ZK")

    def handle_ext(self, pcb):
        """
        Handle beacon extensions.
        """
        # Handle ASMarking extensions:
        for asm in pcb.iter_asms():
            for rev_info in asm.p.exts.revInfos:
                self.rev_ext_handler(rev_info, asm.isd_as())
        # Handle PCB extensions:
        if pcb.is_sibra():
            logging.debug("%s", pcb.sibra_ext)

    def rev_ext_handler(self, rev_info, isd_as):
        logging.info("REV %s: %s" % (isd_as, rev_info))
        # Trigger the removal of PCBs which contain the revoked interface
        self._remove_revoked_pcbs(rev_info=rev_info, if_id=None)
        # Inform the local PS
        self._send_rev_to_local_ps(rev_info=rev_info)

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

    def _create_asm(self, in_if, out_if, ts, prev_hof):
        pcbms = list(self._create_pcbms(in_if, out_if, ts, prev_hof))
        exts = self._create_asm_exts()
        chain = self._get_my_cert()
        _, cert_ver = chain.get_leaf_isd_as_ver()
        return ASMarking.from_values(
            self.addr.isd_as, self._get_my_trc().version, cert_ver, pcbms,
            self._get_if_rev_token(out_if), self.topology.mtu, chain, **exts)

    def _create_pcbms(self, in_if, out_if, ts, prev_hof):
        pcbm = self._create_pcbm(in_if, out_if, ts, prev_hof)
        yield pcbm
        for er in sorted(self.topology.peer_edge_routers):
            in_if = er.interface.if_id
            if (not self.ifid_state[in_if].is_active() and
                    not self._quiet_startup()):
                logging.warning('Peer ifid:%d inactive (not added).', in_if)
                continue
            yield self._create_pcbm(in_if, out_if, ts, pcbm.hof(), xover=True)

    def _create_pcbm(self, in_if, out_if, ts, prev_hof, xover=False):
        hof = HopOpaqueField.from_values(
            self.HOF_EXP_TIME, in_if, out_if, xover=xover)
        hof.set_mac(self.of_gen_key, ts, prev_hof)
        in_info = self._mk_if_info(in_if)
        out_info = self._mk_if_info(out_if)
        return PCBMarking.from_values(
            in_info["remote_ia"], in_info["remote_if"], in_info["mtu"],
            out_info["remote_ia"], out_info["remote_if"],
            hof, self._get_if_rev_token(in_if))

    def _create_asm_exts(self):
        return {"rev_infos": list(self.revs_to_downstream.items())}

    def _terminate_pcb(self, pcb):
        """
        Copies a PCB, terminates it and adds the segment ID.

        Terminating a PCB means adding a opaque field with the egress IF set
        to 0, i.e., there is no AS to forward a packet containing this path
        segment to.
        """
        pcb = pcb.copy()
        asm = self._create_asm(pcb.p.ifID, 0, pcb.get_timestamp(),
                               pcb.last_hof())
        pcb.add_asm(asm)
        return pcb

    def handle_ifid_packet(self, pkt):
        """
        Update the interface state for the corresponding interface.

        :param ipkt: The IFIDPayload.
        :type ipkt: IFIDPayload
        """
        payload = pkt.get_payload()
        ifid = payload.p.relayIF
        if ifid not in self.ifid_state:
            raise SCIONKeyError("Invalid IF %d in IFIDPayload" % ifid)
        er = self.ifid2er[ifid]
        er.interface.to_if_id = payload.p.origIF
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
                state_info = IFStateInfo.from_values(
                    ifid, True, chain.current_element())
                pld = IFStatePayload.from_values([state_info])
                for er in self.topology.get_all_edge_routers():
                    mgmt_packet = self._build_packet(er.addr, dst_port=er.port,
                                                     payload=pld.copy())
                    self.send(mgmt_packet, er.addr, er.port)

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
        start = time.time()
        while self.run_flag.is_set():
            sleep_interval(start, worker_cycle, "BS.worker cycle",
                           self._quiet_startup())
            start = time.time()
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
            now = time.time()
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
        asm = pcb.asm(-1)
        if self._check_trc(asm.isd_as(), asm.p.trcVer):
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
    def _check_trc(self, isd_as, trc_ver):
        """
        Return True or False whether the necessary Certificate and TRC files are
        found.

        :param ISD_AS isd_is: ISD-AS identifier.
        :param int trc_ver: TRC file version.
        """
        raise NotImplementedError

    def _get_my_trc(self):
        return self.trust_store.get_trc(self.addr.isd_as[0])

    def _get_my_cert(self):
        return self.trust_store.get_cert(self.addr.isd_as)

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
            now = int(time.time())
            if (trc_tuple not in self.trc_requests or
                (now - self.trc_requests[trc_tuple] >
                    self.REQUESTS_TIMEOUT)):
                trc_req = TRCRequest.from_values(isd_as, trc_ver)
                logging.info("Requesting %sv%s TRC", isd_as[0], trc_ver)
                try:
                    addr, port = self.dns_query_topo(CERTIFICATE_SERVICE)[0]
                except SCIONServiceLookupError as e:
                    logging.warning("Sending TRC request failed: %s", e)
                    return None
                req_pkt = self._build_packet(addr, dst_port=port,
                                             payload=trc_req)
                self.send(req_pkt, addr, SCION_UDP_EH_DATA_PORT)
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
        asm = pcb.asm(-1)
        cert_ia = asm.isd_as()
        trc = self.trust_store.get_trc(cert_ia[0], asm.p.trcVer)
        return verify_sig_chain_trc(
            pcb.sig_pack(), asm.p.sig, str(cert_ia), asm.chain(), trc,
            asm.p.trcVer)

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
        pld = IFStatePayload.from_values([info])
        for er in self.topology.get_all_edge_routers():
            state_pkt = self._build_packet(er.addr, dst_port=er.port,
                                           payload=pld.copy())
            self.send(state_pkt, er.addr, er.port)
        self._process_revocation(rev_info, if_id)

    def _send_rev_to_local_ps(self, rev_info):
        """
        Sends the given revocation to its local path server.
        :param rev_info: The RevocationInfo object
        :type rev_info: RevocationInfo
        """
        if self.zk.have_lock() and self.topology.path_servers:
            try:
                addr, port = self.dns_query_topo(PATH_SERVICE)[0]
            except SCIONServiceLookupError:
                # If there are no local path servers, stop here.
                return
            pkt = self._build_packet(addr, dst_port=port, payload=rev_info)
            logging.info("Sending revocation to local PS.")
            self.send(pkt, addr, SCION_UDP_EH_DATA_PORT)

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
                        cand.pcb.ifID == if_id):
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
        while self.run_flag.is_set():
            start_time = time.time()
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
        # Only master replies to ifstate requests.
        if not self.zk.have_lock():
            return
        req = mgmt_pkt.get_payload()
        assert isinstance(req, IFStateRequest)
        logging.debug("Received ifstate req:\n%s", mgmt_pkt)
        infos = []
        if req.p.ifID == IFStateRequest.ALL_INTERFACES:
            ifid_states = self.ifid_state.items()
        elif req.p.ifID in self.ifid_state:
            ifid_states = [(req.p.ifID, self.ifid_state[req.p.ifID])]
        else:
            logging.error("Received ifstate request from %s for unknown "
                          "interface %s.", mgmt_pkt.addrs.src, req.p.ifID)
            return

        for (ifid, state) in ifid_states:
            # Don't include inactive interfaces in response.
            if state.is_inactive():
                continue
            chain = self._get_if_hash_chain(ifid)
            info = IFStateInfo.from_values(ifid, state.is_active(),
                                           chain.next_element())
            infos.append(info)
        if not infos and not self._quiet_startup():
            logging.warning("No IF state info to put in response.")
            return

        payload = IFStatePayload.from_values(infos)
        state_pkt = self._build_packet(
            mgmt_pkt.addrs.src.host, dst_port=mgmt_pkt.l4_hdr.src_port,
            payload=payload)
        self.send(state_pkt, mgmt_pkt.addrs.src.host, mgmt_pkt.l4_hdr.src_port)
