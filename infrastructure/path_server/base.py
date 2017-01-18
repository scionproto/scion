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
:mod:`base` --- Base path server
================================
"""
# Stdlib
import logging
import threading
from _collections import defaultdict, deque
from abc import ABCMeta, abstractmethod
from threading import Lock

# External packages
from Crypto.Hash import SHA256
from external.expiring_dict import ExpiringDict

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.hash_tree import ConnectedHashTree
from lib.defines import (
    HASHTREE_EPOCH_TIME,
    HASHTREE_TTL,
    PATH_SERVICE,
)
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.path_mgmt.seg_recs import PathRecordsReply, PathSegmentRecords
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.packet.svc import SVCType
from lib.path_db import DBResult, PathSegmentDB
from lib.thread import thread_safety_net
from lib.types import PathMgmtType as PMT, PathSegmentType as PST, PayloadClass
from lib.util import SCIONTime, sleep_interval
from lib.zk.cache import ZkSharedCache
from lib.zk.errors import ZkNoConnection
from lib.zk.id import ZkID
from lib.zk.zk import Zookeeper


class PathServer(SCIONElement, metaclass=ABCMeta):
    """
    The SCION Path Server.
    """
    SERVICE_TYPE = PATH_SERVICE
    MAX_SEG_NO = 5  # TODO: replace by config variable.
    # ZK path for incoming PATHs
    ZK_PATH_CACHE_PATH = "path_cache"
    # ZK path for incoming REVs
    ZK_REV_CACHE_PATH = "rev_cache"
    # Max number of segments per propagation packet
    PROP_LIMIT = 5
    # Max number of segments per ZK cache entry
    ZK_SHARE_LIMIT = 10
    # Time to store revocations in zookeeper
    ZK_REV_OBJ_MAX_AGE = HASHTREE_EPOCH_TIME

    def __init__(self, server_id, conf_dir):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        """
        super().__init__(server_id, conf_dir)
        self.down_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO)
        self.core_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO)
        self.pending_req = defaultdict(list)  # Dict of pending requests.
        # Used when l/cPS doesn't have up/dw-path.
        self.waiting_targets = defaultdict(list)
        self.revocations = ExpiringDict(1000, HASHTREE_EPOCH_TIME)
        # Contains PCBs that include revocations.
        self.pcb_cache = ExpiringDict(100, HASHTREE_EPOCH_TIME)
        self.pcb_cache_lock = Lock()
        # A mapping from (hash tree root of AS, IFID) to segments
        self.htroot_if2seg = ExpiringDict(1000, HASHTREE_TTL)
        self.htroot_if2seglock = Lock()
        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REQUEST: self.path_resolution,
                PMT.REPLY: self.handle_path_segment_record,
                PMT.REG: self.handle_path_segment_record,
                PMT.REVOCATION: self._handle_revocation,
                PMT.SYNC: self.handle_path_segment_record,
            },
        }
        self.SCMP_PLD_CLASS_MAP = {
            SCMPClass.PATH: {
                SCMPPathClass.REVOKED_IF: self._handle_scmp_revocation,
            },
        }
        self._segs_to_zk = deque()
        self._revs_to_zk = deque()
        self._zkid = ZkID.from_values(self.addr.isd_as, self.id,
                                      [(self.addr.host, self._port)])
        self.zk = Zookeeper(self.topology.isd_as, PATH_SERVICE,
                            self._zkid.copy().pack(), self.topology.zookeepers)
        self.zk.retry("Joining party", self.zk.party_setup)
        self.path_cache = ZkSharedCache(self.zk, self.ZK_PATH_CACHE_PATH,
                                        self._cached_entries_handler)
        self.rev_cache = ZkSharedCache(self.zk, self.ZK_REV_CACHE_PATH,
                                       self._rev_entries_handler)

    def worker(self):
        """
        Worker thread that takes care of reading shared paths from ZK, and
        handling master election for core servers.
        """
        worker_cycle = 1.0
        start = SCIONTime.get_time()
        was_master = False
        while self.run_flag.is_set():
            sleep_interval(start, worker_cycle, "cPS.worker cycle",
                           self._quiet_startup())
            start = SCIONTime.get_time()
            try:
                self.zk.wait_connected()
                self.path_cache.process()
                self.rev_cache.process()
                # Try to become a master.
                is_master = self.zk.get_lock(lock_timeout=0, conn_timeout=0)
                if is_master:
                    if not was_master:
                        logging.info("Became master")
                    self.path_cache.expire(self.config.propagation_time * 10)
                    self.rev_cache.expire(self.ZK_REV_OBJ_MAX_AGE)
                    was_master = True
                else:
                    was_master = False
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')
                pass
            self._update_master()
            self._propagate_and_sync()

    def _cached_entries_handler(self, raw_entries):
        """
        Handles cached through ZK entries, passed as a list.
        """
        count = 0
        for raw in raw_entries:
            recs = PathSegmentRecords.from_raw(raw)
            for type_, pcb in recs.iter_pcbs():
                count += 1
                self._dispatch_segment_record(type_, pcb, from_zk=True)
        if count:
            logging.debug("Processed %s PCBs from ZK", count)

    def _update_master(self):
        pass

    def _rev_entries_handler(self, raw_entries):
        for raw in raw_entries:
            rev_info = RevocationInfo.from_raw(raw)
            self._remove_revoked_segments(rev_info)

    def _add_rev_mappings(self, pcb):
        """
        Add if revocation token to segment ID mappings.
        """
        segment_id = pcb.get_hops_hash()
        with self.htroot_if2seglock:
            for asm in pcb.iter_asms():
                hof = asm.pcbm(0).hof()
                egress_h = (asm.p.hashTreeRoot, hof.egress_if)
                self.htroot_if2seg.setdefault(egress_h, set()).add(segment_id)
                ingress_h = (asm.p.hashTreeRoot, hof.ingress_if)
                self.htroot_if2seg.setdefault(ingress_h, set()).add(segment_id)

    @abstractmethod
    def _handle_up_segment_record(self, pcb, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def _handle_down_segment_record(self, pcb, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def _handle_core_segment_record(self, pcb, **kwargs):
        raise NotImplementedError

    def _add_segment(self, pcb, seg_db, name, reverse=False):
        res = seg_db.update(pcb, reverse=reverse)
        if res == DBResult.ENTRY_ADDED:
            self._add_rev_mappings(pcb)
            logging.info("%s-Segment registered: %s", name, pcb.short_desc())
            return True
        elif res == DBResult.ENTRY_UPDATED:
            self._add_rev_mappings(pcb)
            logging.debug("%s-Segment updated: %s", name, pcb.short_desc())
        return False

    def _handle_scmp_revocation(self, pld, meta):
        rev_info = RevocationInfo.from_raw(pld.info.rev_info)
        self._handle_revocation(rev_info, meta)

    def _handle_revocation(self, rev_info, meta):
        """
        Handles a revocation of a segment, interface or hop.

        :param rev_info: The RevocationInfo object.
        """
        assert isinstance(rev_info, RevocationInfo)
        if not self._validate_revocation(rev_info):
            return
        if meta.ia[0] != self.addr.isd_as[0]:
            logging.info("Dropping revocation received from a different ISD.")
            return

        if rev_info in self.revocations:
            logging.debug("Already received revocation. Dropping...")
            return False
        self.revocations[rev_info] = True
        logging.debug("Received revocation from %s:\n%s",
                      meta.get_addr(), rev_info)
        self._revs_to_zk.append(rev_info.copy().pack())  # have to pack copy
        # Remove segments that contain the revoked interface.
        self._remove_revoked_segments(rev_info)
        # Update revocations for PCBs in the the PCB cache.
        with self.pcb_cache_lock:
            for segment in self.pcb_cache.values():
                segment.add_rev_infos([rev_info.copy()])
        # Forward revocation to other path servers.
        self._forward_revocation(rev_info, meta)

    def _remove_revoked_segments(self, rev_info):
        """
        Try the previous and next hashes as possible astokens,
        and delete any segment that matches

        :param rev_info: The revocation info
        :type rev_info: RevocationInfo
        """
        if not ConnectedHashTree.verify_epoch(rev_info.p.epoch):
            return
        (hash01, hash12) = ConnectedHashTree.get_possible_hashes(rev_info)
        if_id = rev_info.p.ifID

        with self.htroot_if2seglock:
            down_segs_removed = 0
            core_segs_removed = 0
            up_segs_removed = 0
            for h in (hash01, hash12):
                for sid in self.htroot_if2seg.pop((h, if_id), []):
                    if self.down_segments.delete(sid) == DBResult.ENTRY_DELETED:
                        down_segs_removed += 1
                    if self.core_segments.delete(sid) == DBResult.ENTRY_DELETED:
                        core_segs_removed += 1
                    if not self.topology.is_core_as:
                        if (self.up_segments.delete(sid) ==
                                DBResult.ENTRY_DELETED):
                            up_segs_removed += 1
            logging.info("Removed segments containing IF %d: "
                         "UP: %d DOWN: %d CORE: %d" %
                         (if_id, up_segs_removed, down_segs_removed,
                          core_segs_removed))

    @abstractmethod
    def _forward_revocation(self, rev_info, meta):
        """
        Forwards a revocation to other path servers that need to be notified.

        :param rev_info: The RevInfo object.
        :param meta: The MessageMeta object.
        """
        raise NotImplementedError

    def _send_path_segments(self, req, meta, up=None, core=None, down=None):
        """
        Sends path-segments to requester (depending on Path Server's location).
        """
        up = up or set()
        core = core or set()
        down = down or set()
        if not (up | core | down):
            logging.warning("No segments to send")
            return
        pld = PathRecordsReply.from_values(
            {PST.UP: up, PST.CORE: core, PST.DOWN: down},
        )
        self.send_meta(pld, meta)
        logging.info(
            "Sending PATH_REPLY with %d segment(s) to:%s "
            "port:%s in response to: %s", len(up | core | down),
            meta.get_addr(), meta.port, req.short_desc(),
        )

    def _handle_pending_requests(self, dst_ia, sibra):
        to_remove = []
        key = dst_ia, sibra
        # Serve pending requests.
        for req, meta in self.pending_req[key]:
            if self.path_resolution(req, meta, new_request=False):
                meta.close()
                to_remove.append((req, meta))
        # Clean state.
        for req_meta in to_remove:
            self.pending_req[key].remove(req_meta)
        if not self.pending_req[key]:
            del self.pending_req[key]

    def handle_path_segment_record(self, seg_recs, meta):
        meta.close()  # FIXME(PSz): validate before
        params = self._dispatch_params(seg_recs, meta)
        added = set()
        for type_, pcb in seg_recs.iter_pcbs():
            added.update(self._dispatch_segment_record(type_, pcb, **params))
        # Handling pending requests, basing on added segments.
        for dst_ia, sibra in added:
            self._handle_pending_requests(dst_ia, sibra)

    def _dispatch_segment_record(self, type_, seg, **kwargs):
        # Check that segment does not contain a revoked interface.
        if not self._validate_segment(seg):
            logging.debug("Not adding segment due to revoked interface:\n%s" %
                          seg.short_desc())
            return set()
        handle_map = {
            PST.UP: self._handle_up_segment_record,
            PST.CORE: self._handle_core_segment_record,
            PST.DOWN: self._handle_down_segment_record,
        }
        return handle_map[type_](seg, **kwargs)

    def _validate_segment(self, seg):
        """
        Check segment for revoked upstream/downstream interfaces.

        :param seg: The PathSegment object.
        :return: False, if the path segment contains a revoked upstream/
            downstream interface (not peer). True otherwise.
        """
        for rev_info in list(self.revocations):
            if not ConnectedHashTree.verify_epoch(rev_info.p.epoch):
                self.revocations.pop(rev_info)
                continue
            for asm in seg.iter_asms():
                pcbm = asm.pcbm(0)
                if (rev_info.isd_as() == asm.isd_as() and
                        rev_info.p.ifID in [pcbm.p.inIF, pcbm.p.outIF]):
                    logging.debug("Found revoked interface (%d) in segment "
                                  "%s." % (rev_info.p.ifID,
                                           seg.short_desc()))
                    return False
        return True

    def _dispatch_params(self, pld, meta):
        return {}

    def _propagate_and_sync(self):
        self._share_via_zk()
        self._share_revs_via_zk()

    def _gen_prop_recs(self, queue, limit=PROP_LIMIT):
        count = 0
        pcbs = defaultdict(list)
        while queue:
            count += 1
            type_, pcb = queue.popleft()
            pcbs[type_].append(pcb.copy())
            if count >= limit:
                yield(pcbs)
                count = 0
                pcbs = defaultdict(list)
        if pcbs:
            yield(pcbs)

    @abstractmethod
    def path_resolution(self, path_request, meta, new_request):
        """
        Handles all types of path request.
        """
        raise NotImplementedError

    def _add_peer_revs(self, segments):
        """
        Adds revocations to revoked peering interfaces in segments.

        :returns: Set with modified segments. Elements of the original set
            stay untouched.
        """
        # TODO(shitz): This could be optimized, by keeping a map of (ISD_AS, IF)
        # -> RevocationInfo for peer revocations.
        modified_segs = set()
        current_epoch = ConnectedHashTree.get_current_epoch()
        for segment in segments:
            seg_id = segment.get_hops_hash()
            with self.pcb_cache_lock:
                if seg_id in self.pcb_cache:
                    cached_seg = self.pcb_cache[seg_id]
                    logging.debug("Adding segment from PCB cache to response:"
                                  " %s" % cached_seg.short_desc())
                    modified_segs.add(cached_seg)
                    continue
                revs_to_add = set()
                for rev_info in list(self.revocations):
                    if rev_info.p.epoch < current_epoch:
                        self.revocations.pop(rev_info)
                        continue
                    for asm in segment.iter_asms():
                        if asm.isd_as() != rev_info.isd_as():
                            continue
                        for pcbm in asm.iter_pcbms(1):
                            hof = pcbm.hof()
                            if rev_info.p.ifID in [hof.ingress_if,
                                                   hof.egress_if]:
                                revs_to_add.add(rev_info.copy())
                if revs_to_add:
                    new_seg = segment.copy()
                    new_seg.add_rev_infos(list(revs_to_add))
                    logging.debug("Adding revocations to PCB: %s" %
                                  new_seg.short_desc())
                    self.pcb_cache[seg_id] = new_seg
                    modified_segs.add(new_seg)
                else:
                    modified_segs.add(segment)

        return modified_segs

    def _handle_waiting_targets(self, pcb):
        """
        Handle any queries that are waiting for a path to any core AS in an ISD.
        """
        dst_ia = pcb.first_ia()
        if not self.is_core_as(dst_ia):
            logging.warning("Invalid waiting target, not a core AS: %s", dst_ia)
            return
        self._send_waiting_queries(dst_ia[0], pcb)

    def _send_waiting_queries(self, dst_isd, pcb):
        targets = self.waiting_targets[dst_isd]
        if not targets:
            return
        path = pcb.get_path(reverse_direction=True)
        src_ia = pcb.first_ia()
        while targets:
            seg_req = targets.pop(0)
            meta = self.DefaultMeta.from_values(ia=src_ia, path=path,
                                                host=SVCType.PS_A)
            self.send_meta(seg_req, meta)
            logging.info("Waiting request (%s) sent via %s",
                         seg_req.short_desc(), pcb.short_desc())

    def _share_via_zk(self):
        if not self._segs_to_zk:
            return
        logging.info("Sharing %d segment(s) via ZK", len(self._segs_to_zk))
        for pcb_dict in self._gen_prop_recs(self._segs_to_zk,
                                            limit=self.ZK_SHARE_LIMIT):
            seg_recs = PathSegmentRecords.from_values(pcb_dict)
            self._zk_write(seg_recs.pack())

    def _share_revs_via_zk(self):
        if not self._revs_to_zk:
            return
        logging.info("Sharing %d revocation(s) via ZK", len(self._revs_to_zk))
        while self._revs_to_zk:
            self._zk_write_rev(self._revs_to_zk.popleft())

    def _zk_write(self, data):
        hash_ = SHA256.new(data).hexdigest()
        try:
            self.path_cache.store("%s-%s" % (hash_, SCIONTime.get_time()), data)
        except ZkNoConnection:
            logging.warning("Unable to store segment(s) in shared path: "
                            "no connection to ZK")

    def _zk_write_rev(self, data):
        hash_ = SHA256.new(data).hexdigest()
        try:
            self.rev_cache.store("%s-%s" % (hash_, SCIONTime.get_time()), data)
        except ZkNoConnection:
            logging.warning("Unable to store revocation(s) in shared path: "
                            "no connection to ZK")

    def run(self):
        """
        Run an instance of the Path Server.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="PS.worker", daemon=True).start()
        super().run()
