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
from collections import defaultdict
from abc import ABCMeta, abstractmethod
from threading import Lock, RLock

# External packages
from external.expiring_dict import ExpiringDict

# SCION
from infrastructure.scion_elem import SCIONElement
from infrastructure.beacon_server.if_state import InterfaceState
from lib.crypto.hash_tree import ConnectedHashTree
from lib.crypto.symcrypto import kdf
from lib.defines import (
    BEACON_SERVICE,
    HASHTREE_EPOCH_TIME,
    HASHTREE_EPOCH_TOLERANCE,
    HASHTREE_TTL,
    HASHTREE_UPDATE_WINDOW,
    PATH_POLICY_FILE,
    PATH_SERVICE,
)
from lib.errors import (
    SCIONKeyError,
    SCIONParseError,
    SCIONServiceLookupError,
)
from lib.flagtypes import TCPFlags
from lib.msg_meta import TCPMetadata, UDPMetadata
from lib.path_seg_meta import PathSegMeta
from lib.packet.ext.one_hop_path import OneHopPathExt
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.path import SCIONPath
from lib.packet.path_mgmt.ifstate import (
    IFStateInfo,
    IFStatePayload,
    IFStateRequest,
)
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.pcb import (
    ASMarking,
    PathSegment,
    PCBMarking,
)
from lib.packet.scion_addr import ISD_AS
from lib.packet.svc import SVCType
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.path_store import PathPolicy
from lib.thread import thread_safety_net, kill_self
from lib.types import (
    CertMgmtType,
    PathMgmtType as PMT,
    PayloadClass,
)
from lib.util import (
    SCIONTime,
    get_sig_key_file_path,
    read_file,
    sleep_interval,
)
from lib.zk.cache import ZkSharedCache
from lib.zk.errors import ZkNoConnection
from lib.zk.id import ZkID
from lib.zk.zk import ZK_LOCK_SUCCESS, Zookeeper


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
    ZK_REV_OBJ_MAX_AGE = HASHTREE_EPOCH_TIME
    # Interval to checked for timed out interfaces.
    IF_TIMEOUT_INTERVAL = 1

    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
        # TODO: add 2 policies
        self.path_policy = PathPolicy.from_file(
            os.path.join(conf_dir, PATH_POLICY_FILE))
        sig_key_file = get_sig_key_file_path(self.conf_dir)
        self.signing_key = base64.b64decode(read_file(sig_key_file))
        self.of_gen_key = kdf(self.config.master_as_key, b"Derive OF Key")
        self.hashtree_gen_key = kdf(
                            self.config.master_as_key, b"Derive hashtree Key")
        logging.info(self.config.__dict__)
        self._hash_tree = None
        self._hash_tree_lock = Lock()
        self._next_tree = None
        self._init_hash_tree()
        self.ifid_state = {}
        for ifid in self.ifid2br:
            self.ifid_state[ifid] = InterfaceState()
        self.ifid_state_lock = RLock()
        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.PCB: {None: self.handle_pcb},
            PayloadClass.IFID: {None: self.handle_ifid_packet},
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REQ: self.process_cert_chain_request,
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_reply,
                CertMgmtType.TRC_REPLY: self.process_trc_reply,
                CertMgmtType.TRC_REQ: self.process_trc_request,
            },
            PayloadClass.PATH: {
                PMT.IFSTATE_REQ: self._handle_ifstate_request,
                PMT.REVOCATION: self._handle_revocation,
            },
        }
        self.SCMP_PLD_CLASS_MAP = {
            SCMPClass.PATH: {
                SCMPPathClass.REVOKED_IF: self._handle_scmp_revocation,
            },
        }

        zkid = ZkID.from_values(self.addr.isd_as, self.id,
                                [(self.addr.host, self._port)]).pack()
        self.zk = Zookeeper(self.addr.isd_as, BEACON_SERVICE, zkid,
                            self.topology.zookeepers)
        self.zk.retry("Joining party", self.zk.party_setup)
        self.pcb_cache = ZkSharedCache(
            self.zk, self.ZK_PCB_CACHE_PATH, self._handle_pcbs_from_zk)
        self.revobjs_cache = ZkSharedCache(
            self.zk, self.ZK_REVOCATIONS_PATH, self.process_rev_objects)
        self.local_rev_cache = ExpiringDict(1000, HASHTREE_EPOCH_TIME +
                                            HASHTREE_EPOCH_TOLERANCE)
        self._rev_seg_lock = RLock()

    def _init_hash_tree(self):
        ifs = list(self.ifid2br.keys())
        self._hash_tree = ConnectedHashTree(self.addr.isd_as,
                                            ifs, self.hashtree_gen_key)

    def _get_ht_proof(self, if_id):
        with self._hash_tree_lock:
            return self._hash_tree.get_proof(if_id)

    def _get_ht_root(self):
        with self._hash_tree_lock:
            return self._hash_tree.get_root()

    def propagate_downstream_pcb(self, pcb):
        """
        Propagates the beacon to all children.

        :param pcb: path segment.
        :type pcb: PathSegment
        """
        for intf in self.topology.child_interfaces:
            if not intf.to_if_id:
                continue
            new_pcb, meta = self._mk_prop_pcb_meta(
                pcb.copy(), intf.isd_as, intf.if_id)
            if not new_pcb:
                continue
            self.send_meta(new_pcb, meta)
            logging.info("Downstream PCB propagated to %s via IF %s",
                         intf.isd_as, intf.if_id)

    def _mk_prop_pcb_meta(self, pcb, dst_ia, egress_if):
        ts = pcb.get_timestamp()
        asm = self._create_asm(pcb.p.ifID, egress_if, ts, pcb.last_hof())
        if not asm:
            return None, None
        pcb.add_asm(asm)
        pcb.sign(self.signing_key)
        one_hop_path = self._create_one_hop_path(egress_if)
        if self.DefaultMeta == TCPMetadata:
            return pcb, self.DefaultMeta.from_values(
                ia=dst_ia, host=SVCType.BS_A, path=one_hop_path,
                flags=TCPFlags.ONEHOPPATH)
        return pcb, UDPMetadata.from_values(
            ia=dst_ia, host=SVCType.BS_A, path=one_hop_path,
            ext_hdrs=[OneHopPathExt()])

    def _create_one_hop_path(self, egress_if):
        ts = int(SCIONTime.get_time())
        info = InfoOpaqueField.from_values(ts, self.addr.isd_as[0], hops=2)
        hf1 = HopOpaqueField.from_values(self.HOF_EXP_TIME, 0, egress_if)
        hf1.set_mac(self.of_gen_key, ts, None)
        # Return a path where second HF is empty.
        return SCIONPath.from_values(info, [hf1, HopOpaqueField()])

    def _mk_if_info(self, if_id):
        """
        Small helper method to make it easier to deal with ingress/egress
        interface being 0 while building ASMarkings.
        """
        d = {"remote_ia": ISD_AS.from_values(0, 0), "remote_if": 0, "mtu": 0}
        if not if_id:
            return d
        br = self.ifid2br[if_id]
        d["remote_ia"] = br.interfaces[if_id].isd_as
        d["remote_if"] = br.interfaces[if_id].to_if_id
        d["mtu"] = br.interfaces[if_id].mtu
        return d

    @abstractmethod
    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        raise NotImplementedError

    def _handle_pcbs_from_zk(self, pcbs):
        """
        Handles cached pcbs through ZK, passed as a list.
        """
        for pcb in pcbs:
            try:
                pcb = PathSegment.from_raw(pcb)
            except SCIONParseError as e:
                logging.error("Unable to parse raw pcb: %s", e)
                continue
            self.handle_pcb(pcb)
        logging.debug("Processed %s PCBs from ZK", len(pcbs))

    def handle_pcb(self, pcb, meta=None):
        """
        Handles pcbs received from the network.
        """
        if meta:
            pcb.p.ifID = meta.path.get_hof().ingress_if
        if not self.path_policy.check_filters(pcb):
            logging.debug("Segment dropped due to path policy: %s" %
                          pcb.short_desc())
            return
        if not self._filter_pcb(pcb):
            logging.debug("Segment dropped due to looping: %s" %
                          pcb.short_desc())
            return
        seg_meta = PathSegMeta(pcb, self.continue_seg_processing, meta)
        self.process_path_seg(seg_meta)

    def continue_seg_processing(self, seg_meta):
        """
        For every pcb(that can be verified) received from the network or ZK
        this function gets called to continue the processing for the pcb.
        """
        pcb = seg_meta.seg
        if seg_meta.meta:
            # Segment was received from network, not from zk. Share segment
            # with other beacon servers in this AS.
            entry_name = "%s-%s" % (pcb.get_hops_hash(hex=True), time.time())
            try:
                self.pcb_cache.store(entry_name, pcb.copy().pack())
            except ZkNoConnection:
                logging.error("Unable to store PCB in shared cache: "
                              "no connection to ZK")
        self._handle_verified_beacon(pcb)
        self.handle_ext(pcb)

    def _filter_pcb(self, pcb, dst_ia=None):
        return True

    def handle_ext(self, pcb):
        """
        Handle beacon extensions.
        """
        # Handle PCB extensions:
        if pcb.is_sibra():
            logging.debug("%s", pcb.sibra_ext)

    @abstractmethod
    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        raise NotImplementedError

    def _create_asm(self, in_if, out_if, ts, prev_hof):
        pcbms = list(self._create_pcbms(in_if, out_if, ts, prev_hof))
        if not pcbms:
            return None
        chain = self._get_my_cert()
        _, cert_ver = chain.get_leaf_isd_as_ver()
        return ASMarking.from_values(
            self.addr.isd_as, self._get_my_trc().version, cert_ver, pcbms,
            self._get_ht_root(), self.topology.mtu)

    def _create_pcbms(self, in_if, out_if, ts, prev_hof):
        up_pcbm = self._create_pcbm(in_if, out_if, ts, prev_hof)
        if not up_pcbm:
            return
        yield up_pcbm
        for intf in sorted(self.topology.peer_interfaces):
            in_if = intf.if_id
            with self.ifid_state_lock:
                if (not self.ifid_state[in_if].is_active() and
                        not self._quiet_startup()):
                    logging.warning('Peer ifid:%d inactive (not added).', in_if)
                    continue
            peer_pcbm = self._create_pcbm(in_if, out_if, ts, up_pcbm.hof(),
                                          xover=True)
            if peer_pcbm:
                yield peer_pcbm

    def _create_pcbm(self, in_if, out_if, ts, prev_hof, xover=False):
        in_info = self._mk_if_info(in_if)
        if in_info["remote_ia"].int() and not in_info["remote_if"]:
            return None
        out_info = self._mk_if_info(out_if)
        if out_info["remote_ia"].int() and not out_info["remote_if"]:
            return None
        hof = HopOpaqueField.from_values(
            self.HOF_EXP_TIME, in_if, out_if, xover=xover)
        hof.set_mac(self.of_gen_key, ts, prev_hof)
        return PCBMarking.from_values(
            in_info["remote_ia"], in_info["remote_if"], in_info["mtu"],
            out_info["remote_ia"], out_info["remote_if"], hof)

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
        if not asm:
            return None
        pcb.add_asm(asm)
        return pcb

    def handle_ifid_packet(self, pld, meta):
        """
        Update the interface state for the corresponding interface.

        :param pld: The IFIDPayload.
        :type pld: IFIDPayload
        """
        ifid = pld.p.relayIF
        with self.ifid_state_lock:
            if ifid not in self.ifid_state:
                raise SCIONKeyError("Invalid IF %d in IFIDPayload" % ifid)
            br = self.ifid2br[ifid]
            br.interfaces[ifid].to_if_id = pld.p.origIF
            prev_state = self.ifid_state[ifid].update()
            if prev_state == InterfaceState.INACTIVE:
                logging.info("IF %d activated", ifid)
            elif prev_state in [InterfaceState.TIMED_OUT,
                                InterfaceState.REVOKED]:
                logging.info("IF %d came back up.", ifid)
            if not prev_state == InterfaceState.ACTIVE:
                if self.zk.have_lock():
                    # Inform BRs about the interface coming up.
                    state_info = IFStateInfo.from_values(
                        ifid, True, self._get_ht_proof(ifid))
                    pld = IFStatePayload.from_values([state_info])
                    for br in self.topology.border_routers:
                        br_addr, br_port = br.int_addrs[0].public[0]
                        meta = UDPMetadata.from_values(
                            host=br_addr, port=br_port)
                        self.send_meta(pld.copy(), meta, (br_addr, br_port))

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
        threading.Thread(
            target=thread_safety_net, args=(self._create_next_tree,),
            name="BS._create_next_tree", daemon=True).start()
        super().run()

    def _create_next_tree(self):
        last_ttl_window = 0
        while self.run_flag.is_set():
            start = time.time()
            cur_ttl_window = ConnectedHashTree.get_ttl_window()
            time_to_sleep = (ConnectedHashTree.get_time_till_next_ttl() -
                             HASHTREE_UPDATE_WINDOW)
            if cur_ttl_window == last_ttl_window:
                time_to_sleep += HASHTREE_TTL
            if time_to_sleep > 0:
                sleep_interval(start, time_to_sleep, "BS._create_next_tree",
                               self._quiet_startup())

            # at this point, there should be <= HASHTREE_UPDATE_WINDOW
            # seconds left in current ttl
            logging.info("Started computing hashtree for next ttl")
            last_ttl_window = ConnectedHashTree.get_ttl_window()

            ifs = list(self.ifid2br.keys())
            tree = ConnectedHashTree.get_next_tree(self.addr.isd_as, ifs,
                                                   self.hashtree_gen_key)
            with self._hash_tree_lock:
                self._next_tree = tree

    def _maintain_hash_tree(self):
        """
        Maintain the hashtree. Update the the windows in the connected tree
        """
        with self._hash_tree_lock:
            if self._next_tree is not None:
                self._hash_tree.update(self._next_tree)
                self._next_tree = None
            else:
                logging.critical("Did not create hashtree in time; dying")
                kill_self()
        logging.info("New Hash Tree TTL beginning")

    def worker(self):
        """
        Worker thread that takes care of reading shared PCBs from ZK, and
        propagating PCBS/registering paths when master.
        """
        last_propagation = last_registration = 0
        last_ttl_window = ConnectedHashTree.get_ttl_window()
        worker_cycle = 1.0
        start = time.time()
        while self.run_flag.is_set():
            sleep_interval(start, worker_cycle, "BS.worker cycle",
                           self._quiet_startup())
            start = time.time()
            try:
                self.zk.wait_connected()
                self.pcb_cache.process()
                self.revobjs_cache.process()
                self.handle_rev_objs()

                cur_ttl_window = ConnectedHashTree.get_ttl_window()
                if cur_ttl_window != last_ttl_window:
                    self._maintain_hash_tree()
                    last_ttl_window = cur_ttl_window

                ret = self.zk.get_lock(lock_timeout=0, conn_timeout=0)
                if not ret:  # Failed to get the lock
                    continue
                elif ret == ZK_LOCK_SUCCESS:
                    logging.info("Became master")
                    self._became_master()
                self.pcb_cache.expire(self.config.propagation_time * 10)
                self.revobjs_cache.expire(self.ZK_REV_OBJ_MAX_AGE)
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
        with self.ifid_state_lock:
            for (_, ifstate) in self.ifid_state.items():
                if not ifstate.is_active():
                    ifstate.reset()

    def _get_my_trc(self):
        return self.trust_store.get_trc(self.addr.isd_as[0])

    def _get_my_cert(self):
        return self.trust_store.get_cert(self.addr.isd_as)

    @abstractmethod
    def _handle_verified_beacon(self, pcb):
        """
        Once a beacon has been verified, place it into the right containers.

        :param pcb: verified path segment.
        :type pcb: PathSegment
        """
        raise NotImplementedError

    def process_rev_objects(self, rev_infos):
        """
        Processes revocation infos stored in Zookeeper.
        """
        with self._rev_seg_lock:
            for raw in rev_infos:
                try:
                    rev_info = RevocationInfo.from_raw(raw)
                except SCIONParseError as e:
                    logging.error(
                        "Error processing revocation info from ZK: %s", e)
                    continue
                self.local_rev_cache[rev_info] = rev_info.copy()

    def _issue_revocation(self, if_id):
        """
        Store a RevocationInfo in ZK and send a revocation to all BRs.

        :param if_id: The interface that needs to be revoked.
        :type if_id: int
        """
        # Only the master BS issues revocations.
        if not self.zk.have_lock():
            return
        rev_info = self._get_ht_proof(if_id)
        logging.error("Issuing revocation for IF %d.", if_id)
        # Issue revocation to all BRs.
        info = IFStateInfo.from_values(if_id, False, rev_info)
        pld = IFStatePayload.from_values([info])
        for br in self.topology.border_routers:
            br_addr, br_port = br.int_addrs[0].public[0]
            meta = UDPMetadata.from_values(host=br_addr, port=br_port)
            self.send_meta(pld.copy(), meta, (br_addr, br_port))
        self._process_revocation(rev_info)
        self._send_rev_to_local_ps(rev_info)

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
            logging.info("Sending revocation to local PS.")
            meta = UDPMetadata.from_values(host=addr, port=port)
            self.send_meta(rev_info.copy(), meta)

    def _handle_scmp_revocation(self, pld, meta):
        rev_info = RevocationInfo.from_raw(pld.info.rev_info)
        logging.info("Received revocation via SCMP:\n%s", rev_info.short_desc())
        self._process_revocation(rev_info)

    def _handle_revocation(self, rev_info, meta):
        logging.info("Received revocation via TCP/UDP:\n%s",
                     rev_info.short_desc())
        if not self._validate_revocation(rev_info):
            return
        self._process_revocation(rev_info)

    def handle_rev_objs(self):
        with self._rev_seg_lock:
            for rev_info in self.local_rev_cache.values():
                self._remove_revoked_pcbs(rev_info)

    def _process_revocation(self, rev_info):
        """
        Removes PCBs containing a revoked interface and sends the revocation
        to the local PS.

        :param rev_info: The RevocationInfo object
        :type rev_info: RevocationInfo
        """
        assert isinstance(rev_info, RevocationInfo)
        if_id = rev_info.p.ifID
        if not if_id:
            logging.error("Trying to revoke IF with ID 0.")
            return
        with self._rev_seg_lock:
            self.local_rev_cache[rev_info] = rev_info.copy()
        logging.info("Storing revocation in ZK.")
        rev_token = rev_info.copy().pack()
        entry_name = "%s:%s" % (hash(rev_token), time.time())
        try:
            self.revobjs_cache.store(entry_name, rev_token)
        except ZkNoConnection as exc:
            logging.error("Unable to store revocation in shared cache "
                          "(no ZK connection): %s" % exc)
        self._remove_revoked_pcbs(rev_info)

    @abstractmethod
    def _remove_revoked_pcbs(self, rev_info):
        """
        Removes the PCBs containing the revoked interface.

        :param rev_info: The RevocationInfo object.
        :type rev_info: RevocationInfo
        """
        raise NotImplementedError

    def _pcb_list_to_remove(self, candidates, rev_info):
        """
        Calculates the list of PCBs to remove.
        Called by _remove_revoked_pcbs.

        :param candidates: Candidate PCBs.
        :type candidates: List
        :param rev_info: The RevocationInfo object.
        :type rev_info: RevocationInfo
        """
        to_remove = []
        processed = set()
        for cand in candidates:
            if cand.id in processed:
                continue
            processed.add(cand.id)
            if not ConnectedHashTree.verify_epoch(rev_info.p.epoch):
                continue

            # If the interface on which we received the PCB is
            # revoked, then the corresponding pcb needs to be removed, if
            # the proof can be verified with the own AS's root for the current
            # epoch and  the if_id of the interface on which pcb was received
            # matches that in the rev_info
            root_verify = ConnectedHashTree.verify(
                            rev_info, self._get_ht_root())
            if (self.addr.isd_as == rev_info.isd_as() and
                    cand.pcb.p.ifID == rev_info.p.ifID and root_verify):
                to_remove.append(cand.id)

            for asm in cand.pcb.iter_asms():
                if self._verify_revocation_for_asm(rev_info, asm, False):
                    to_remove.append(cand.id)

        return to_remove

    def _handle_if_timeouts(self):
        """
        Periodically checks each interface state and issues an if revocation, if
        no keep-alive message was received for IFID_TOUT.
        """
        if_id_last_revoked = defaultdict(int)
        while self.run_flag.is_set():
            start_time = time.time()
            with self.ifid_state_lock:
                for (if_id, if_state) in self.ifid_state.items():
                    cur_epoch = ConnectedHashTree.get_current_epoch()
                    if not if_state.is_expired() or (
                            if_state.is_revoked() and if_id_last_revoked[if_id] == cur_epoch):
                        # Either the interface hasn't timed out, or it's already revoked for this
                        # epoch
                        continue
                    if_id_last_revoked[if_id] = cur_epoch
                    if not if_state.is_revoked():
                        logging.info("IF %d appears to be down.", if_id)
                    self._issue_revocation(if_id)
                    if_state.revoke_if_expired()
            sleep_interval(start_time, self.IF_TIMEOUT_INTERVAL,
                           "Handle IF timeouts")

    def _handle_ifstate_request(self, req, meta):
        # Only master replies to ifstate requests.
        if not self.zk.have_lock():
            return
        assert isinstance(req, IFStateRequest)
        logging.debug("Received ifstate req:\n%s", req)
        infos = []
        with self.ifid_state_lock:
            if req.p.ifID == IFStateRequest.ALL_INTERFACES:
                ifid_states = self.ifid_state.items()
            elif req.p.ifID in self.ifid_state:
                ifid_states = [(req.p.ifID, self.ifid_state[req.p.ifID])]
            else:
                logging.error("Received ifstate request from %s for unknown "
                              "interface %s.", meta.get_addr(), req.p.ifID)
                return

            for (ifid, state) in ifid_states:
                # Don't include inactive interfaces in response.
                if state.is_inactive():
                    continue
                info = IFStateInfo.from_values(ifid, state.is_active(),
                                               self._get_ht_proof(ifid))
                infos.append(info)
        if not infos and not self._quiet_startup():
            logging.warning("No IF state info to put in response.")
            return
        payload = IFStatePayload.from_values(infos)
        self.send_meta(payload, meta, (meta.host, meta.port))
