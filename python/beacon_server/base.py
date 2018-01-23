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
import logging
import os
import threading
import time
from collections import defaultdict
from abc import ABCMeta, abstractmethod
from threading import Lock, RLock

# External packages
from external.expiring_dict import ExpiringDict
from prometheus_client import Counter, Gauge

# SCION
from beacon_server.if_state import InterfaceState
from lib.crypto.asymcrypto import get_sig_key
from lib.crypto.hash_tree import ConnectedHashTree
from lib.crypto.symcrypto import kdf
from lib.defines import (
    BEACON_SERVICE,
    EXP_TIME_UNIT,
    HASHTREE_EPOCH_TIME,
    HASHTREE_EPOCH_TOLERANCE,
    PATH_POLICY_FILE,
    PATH_SERVICE,
)
from lib.errors import (
    SCIONBaseError,
    SCIONKeyError,
    SCIONParseError,
    SCIONPathPolicyViolated,
    SCIONServiceLookupError,
)
from lib.msg_meta import UDPMetadata
from lib.path_seg_meta import PathSegMeta
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.ifid import IFIDPayload
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.path import SCIONPath
from lib.packet.path_mgmt.base import PathMgmt
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
    HashType,
    PathMgmtType as PMT,
    PayloadClass,
)
from lib.util import (
    SCIONTime,
    sleep_interval,
)
from lib.zk.cache import ZkSharedCache
from lib.zk.errors import ZkNoConnection
from lib.zk.id import ZkID
from lib.zk.zk import ZK_LOCK_SUCCESS, Zookeeper
from scion_elem.scion_elem import SCIONElement


# Exported metrics.
BEACONS_PROPAGATED = Counter("bs_beacons_propagated_total", "# of propagated beacons",
                             ["server_id", "isd_as", "type"])
SEGMENTS_REGISTERED = Counter("bs_segments_registered_total", "# of registered segments",
                              ["server_id", "isd_as", "type"])
REVOCATIONS_ISSUED = Counter("bs_revocations_issued_total", "# of issued revocations",
                             ["server_id", "isd_as"])
IS_MASTER = Gauge("bs_is_master", "true if this process is the replication master",
                  ["server_id", "isd_as"])


class BeaconServer(SCIONElement, metaclass=ABCMeta):
    """
    The SCION PathConstructionBeacon Server.

    Attributes:
        if2rev_tokens: Contains the currently used revocation token
            hash-chain for each interface.
    """
    SERVICE_TYPE = BEACON_SERVICE
    # ZK path for incoming PCBs
    ZK_PCB_CACHE_PATH = "pcb_cache"
    # ZK path for revocations.
    ZK_REVOCATIONS_PATH = "rev_cache"
    # Time revocation objects are cached in memory (in seconds).
    ZK_REV_OBJ_MAX_AGE = HASHTREE_EPOCH_TIME
    # Interval to checked for timed out interfaces.
    IF_TIMEOUT_INTERVAL = 1

    def __init__(self, server_id, conf_dir, prom_export=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        super().__init__(server_id, conf_dir, prom_export=prom_export)
        # TODO: add 2 policies
        self.path_policy = PathPolicy.from_file(
            os.path.join(conf_dir, PATH_POLICY_FILE))
        self.signing_key = get_sig_key(self.conf_dir)
        self.of_gen_key = kdf(self.config.master_as_key, b"Derive OF Key")
        self.hashtree_gen_key = kdf(
                            self.config.master_as_key, b"Derive hashtree Key")
        logging.info(self.config.__dict__)
        # Amount of time units a HOF is valid (time unit is EXP_TIME_UNIT).
        self.hof_exp_time = int(self.config.segment_ttl / EXP_TIME_UNIT)
        self._hash_tree = None
        self._hash_tree_lock = Lock()
        self._next_tree = None
        self._init_hash_tree()
        self.ifid_state = {}
        for ifid in self.ifid2br:
            self.ifid_state[ifid] = InterfaceState()
        self.ifid_state_lock = RLock()
        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.PCB: {PayloadClass.PCB: self.handle_pcb},
            PayloadClass.IFID: {PayloadClass.IFID: self.handle_ifid_packet},
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
        self._hash_tree = ConnectedHashTree(self.addr.isd_as, ifs, self.hashtree_gen_key,
                                            self.config.revocation_tree_ttl, HashType.SHA256)

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
        propagated_pcbs = defaultdict(list)
        prop_cnt = 0
        for intf in self.topology.child_interfaces:
            if not intf.to_if_id:
                continue
            new_pcb, meta = self._mk_prop_pcb_meta(
                pcb.copy(), intf.isd_as, intf.if_id)
            if not new_pcb:
                continue
            self.send_meta(CtrlPayload(new_pcb), meta)
            propagated_pcbs[(intf.isd_as, intf.if_id)].append(pcb.short_id())
            prop_cnt += 1
        if self._labels:
            BEACONS_PROPAGATED.labels(**self._labels, type="down").inc(prop_cnt)
        return propagated_pcbs

    def _mk_prop_pcb_meta(self, pcb, dst_ia, egress_if):
        ts = pcb.get_timestamp()
        asm = self._create_asm(pcb.p.ifID, egress_if, ts, pcb.last_hof())
        if not asm:
            return None, None
        pcb.add_asm(asm)
        pcb.sign(self.signing_key)
        one_hop_path = self._create_one_hop_path(egress_if)
        return pcb, self._build_meta(ia=dst_ia, host=SVCType.BS_A,
                                     path=one_hop_path, one_hop=True)

    def _create_one_hop_path(self, egress_if):
        ts = int(SCIONTime.get_time())
        info = InfoOpaqueField.from_values(ts, self.addr.isd_as[0], hops=2)
        hf1 = HopOpaqueField.from_values(self.hof_exp_time, 0, egress_if)
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

    def _log_propagations(self, propagated_pcbs):
        for (isd_as, if_id), pcbs in propagated_pcbs.items():
            logging.debug("Propagated %d PCBs to %s via %s (%s)", len(pcbs),
                          isd_as, if_id, ", ".join(pcbs))

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
            self.handle_pcb(CtrlPayload(pcb))
        if pcbs:
            logging.debug("Processed %s PCBs from ZK", len(pcbs))

    def handle_pcb(self, cpld, meta=None):
        """
        Handles pcbs received from the network.
        """
        pcb = cpld.union
        assert isinstance(pcb, PathSegment), type(pcb)
        if meta:
            pcb.p.ifID = meta.path.get_hof().ingress_if
        try:
            self.path_policy.check_filters(pcb)
        except SCIONPathPolicyViolated as e:
            logging.debug("Segment dropped due to path policy: %s\n%s" %
                          (e, pcb.short_desc()))
            return
        if not self._filter_pcb(pcb):
            logging.debug("Segment dropped due to looping: %s" %
                          pcb.short_desc())
            return
        seg_meta = PathSegMeta(pcb, self.continue_seg_processing, meta)
        self._process_path_seg(seg_meta)

    def continue_seg_processing(self, seg_meta):
        """
        For every verified pcb received from the network or ZK
        this function gets called to continue the processing for the pcb.
        """
        pcb = seg_meta.seg
        logging.debug("Successfully verified PCB %s", pcb.short_id())
        if seg_meta.meta:
            # Segment was received from network, not from zk. Share segment
            # with other beacon servers in this AS.
            entry_name = "%s-%s" % (pcb.get_hops_hash(hex=True), time.time())
            try:
                self.pcb_cache.store(entry_name, pcb.copy().pack())
            except ZkNoConnection:
                logging.error("Unable to store PCB in shared cache: "
                              "no connection to ZK")
        self.handle_ext(pcb)
        self._handle_verified_beacon(pcb)

    def _filter_pcb(self, pcb, dst_ia=None):
        return True

    def handle_ext(self, pcb):
        """
        Handle beacon extensions.
        """
        # Handle PCB extensions
        if pcb.is_sibra():
            logging.debug("%s", pcb.sibra_ext)
        for asm in pcb.iter_asms():
            pol = asm.routing_pol_ext()
            if pol:
                self.handle_routing_pol_ext(pol)

    def handle_routing_pol_ext(self, ext):
        # TODO(Sezer): Implement routing policy extension handling
        logging.debug("Routing policy extension: %s" % ext)

    @abstractmethod
    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        raise NotImplementedError

    def _log_registrations(self, registrations, seg_type):
        reg_cnt = 0
        for (dst_meta, dst_type), pcbs in registrations.items():
            reg_cnt += len(pcbs)
            logging.debug("Registered %d %s-segments @ %s:%s (%s)", len(pcbs),
                          seg_type, dst_type.upper(), dst_meta, ", ".join(pcbs))
        if self._labels:
            SEGMENTS_REGISTERED.labels(**self._labels, type=seg_type).inc(reg_cnt)

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
            self.hof_exp_time, in_if, out_if, xover=xover)
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

    def handle_ifid_packet(self, cpld, meta):
        """
        Update the interface state for the corresponding interface.

        :param pld: The IFIDPayload.
        :type pld: IFIDPayload
        """
        pld = cpld.union
        assert isinstance(pld, IFIDPayload), type(pld)
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
                    metas = []
                    for br in self.topology.border_routers:
                        br_addr, br_port = br.int_addrs[0].public[0]
                        metas.append(UDPMetadata.from_values(host=br_addr, port=br_port))
                    self._send_ifstate_update(metas)

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
        threading.Thread(
            target=thread_safety_net, args=(self._check_trc_cert_reqs,),
            name="Elem.check_trc_cert_reqs", daemon=True).start()
        super().run()

    def _create_next_tree(self):
        last_ttl_window = 0
        ttl = self.config.revocation_tree_ttl
        update_window = ttl // 3
        while self.run_flag.is_set():
            start = time.time()
            cur_ttl_window = ConnectedHashTree.get_ttl_window(ttl)
            time_to_sleep = ConnectedHashTree.time_until_next_window(ttl) - update_window
            if cur_ttl_window == last_ttl_window:
                time_to_sleep += ttl
            if time_to_sleep > 0:
                sleep_interval(start, time_to_sleep, "BS._create_next_tree",
                               self._quiet_startup())

            # at this point, there should be <= update_window
            # seconds left in current ttl
            logging.info("Started computing hashtree for next TTL window (%d)",
                         cur_ttl_window + 2)
            last_ttl_window = ConnectedHashTree.get_ttl_window(ttl)

            ht_start = time.time()
            ifs = list(self.ifid2br.keys())
            tree = ConnectedHashTree.get_next_tree(
                self.addr.isd_as, ifs, self.hashtree_gen_key, ttl, HashType.SHA256)
            ht_end = time.time()
            with self._hash_tree_lock:
                self._next_tree = tree
            logging.info("Finished computing hashtree for TTL window %d in %.3fs" %
                         (cur_ttl_window + 2, ht_end - ht_start))

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
        logging.info("New Hash Tree TTL window beginning: %s",
                     ConnectedHashTree.get_ttl_window(self.config.revocation_tree_ttl))

    def worker(self):
        """
        Worker thread that takes care of reading shared PCBs from ZK, and
        propagating PCBS/registering paths when master.
        """
        last_propagation = last_registration = 0
        last_ttl_window = ConnectedHashTree.get_ttl_window(self.config.revocation_tree_ttl)
        worker_cycle = 1.0
        start = time.time()
        while self.run_flag.is_set():
            sleep_interval(start, worker_cycle, "BS.worker cycle",
                           self._quiet_startup())
            start = time.time()
            # Update IS_MASTER metric.
            if self._labels:
                IS_MASTER.labels(**self._labels).set(int(self.zk.have_lock()))
            try:
                self.zk.wait_connected()
                self.pcb_cache.process()
                self.revobjs_cache.process()
                self.handle_rev_objs()

                cur_ttl_window = ConnectedHashTree.get_ttl_window(self.config.revocation_tree_ttl)
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
                    logging.error("Error while registering segments: %s", e)
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

    def _issue_revocations(self, revoked_ifs):
        """
        Store a RevocationInfo in ZK and send a revocation to all BRs.

        :param list revoked_ifs: A list of interfaces that needs to be revoked.
        """
        # Only the master BS issues revocations.
        if not self.zk.have_lock():
            return
        # Process revoked interfaces.
        for if_id in revoked_ifs:
            rev_info = self._get_ht_proof(if_id)
            logging.info("Issuing revocation: %s", rev_info.short_desc())
            if self._labels:
                REVOCATIONS_ISSUED.labels(**self._labels).inc()
            self._process_revocation(rev_info)
        border_metas = []
        # Add all BRs.
        for br in self.topology.border_routers:
            br_addr, br_port = br.int_addrs[0].public[0]
            border_metas.append(UDPMetadata.from_values(host=br_addr, port=br_port))
        # Add local path server.
        ps_meta = []
        if self.topology.path_servers:
            try:
                addr, port = self.dns_query_topo(PATH_SERVICE)[0]
            except SCIONServiceLookupError:
                addr, port = None, None
            # Create a meta if there is a local path service
            if addr:
                ps_meta.append(UDPMetadata.from_values(host=addr, port=port))
        self._send_ifstate_update(border_metas, ps_meta)

    def _handle_scmp_revocation(self, pld, meta):
        rev_info = RevocationInfo.from_raw(pld.info.rev_info)
        logging.debug("Received revocation via SCMP: %s (from %s)", rev_info.short_desc(), meta)
        self._process_revocation(rev_info)

    def _handle_revocation(self, cpld, meta):
        pmgt = cpld.union
        rev_info = pmgt.union
        assert isinstance(rev_info, RevocationInfo), type(rev_info)
        logging.debug("Received revocation via TCP/UDP: %s (from %s)", rev_info.short_desc(), meta)
        try:
            rev_info.validate()
        except SCIONBaseError as e:
            logging.warning("Failed to validate RevInfo from %s: %s", meta, e)
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
        assert isinstance(rev_info, RevocationInfo), type(rev_info)
        if_id = rev_info.p.ifID
        if not if_id:
            logging.error("Trying to revoke IF with ID 0.")
            return
        with self._rev_seg_lock:
            self.local_rev_cache[rev_info] = rev_info.copy()
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
            if ConnectedHashTree.verify_epoch(rev_info.p.epoch) != ConnectedHashTree.EPOCH_OK:
                continue

            # If the interface on which we received the PCB is
            # revoked, then the corresponding pcb needs to be removed.
            root_verify = ConnectedHashTree.verify(rev_info, self._get_ht_root())
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
                to_revoke = []
                for (if_id, if_state) in self.ifid_state.items():
                    cur_epoch = ConnectedHashTree.get_current_epoch()
                    if not if_state.is_expired() or (
                            if_state.is_revoked() and if_id_last_revoked[if_id] == cur_epoch):
                        # Either the interface hasn't timed out, or it's already revoked for this
                        # epoch
                        continue
                    if_id_last_revoked[if_id] = cur_epoch
                    if not if_state.is_revoked():
                        logging.info("IF %d went down.", if_id)
                    to_revoke.append(if_id)
                    if_state.revoke_if_expired()
                self._issue_revocations(to_revoke)
            sleep_interval(start_time, self.IF_TIMEOUT_INTERVAL,
                           "Handle IF timeouts")

    def _handle_ifstate_request(self, cpld, meta):
        # Only master replies to ifstate requests.
        pmgt = cpld.union
        req = pmgt.union
        assert isinstance(req, IFStateRequest), type(req)
        if not self.zk.have_lock():
            return
        self._send_ifstate_update([meta])

    def _send_ifstate_update(self, border_metas, server_metas=None):
        server_metas = server_metas or []
        with self.ifid_state_lock:
            infos = []
            for (ifid, state) in self.ifid_state.items():
                # Don't include inactive interfaces in update.
                if state.is_inactive():
                    continue
                rev_info = self._get_ht_proof(ifid) if state.is_revoked() else None
                info = IFStateInfo.from_values(ifid, state.is_active(), rev_info)
                infos.append(info)
            if not infos and not self._quiet_startup():
                logging.warning("No IF state info to put in IFState update for %s.",
                                ", ".join([str(m) for m in border_metas + server_metas]))
                return
            payload = CtrlPayload(PathMgmt(IFStatePayload.from_values(infos)))
        for meta in border_metas:
            self.send_meta(payload.copy(), meta, (meta.host, meta.port))
        for meta in server_metas:
            self.send_meta(payload.copy(), meta)

    def _init_metrics(self):
        super()._init_metrics()
        for type_ in ("core", "up", "down"):
            BEACONS_PROPAGATED.labels(**self._labels, type=type_).inc(0)
            SEGMENTS_REGISTERED.labels(**self._labels, type=type_).inc(0)
        REVOCATIONS_ISSUED.labels(**self._labels).inc(0)
        IS_MASTER.labels(**self._labels).set(0)
