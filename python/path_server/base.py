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
from collections import defaultdict
from abc import ABCMeta, abstractmethod
from threading import Lock

# External packages
from external.expiring_dict import ExpiringDict
from prometheus_client import Counter, Gauge

# SCION
from lib.crypto.symcrypto import crypto_hash
from lib.defines import (
    GEN_CACHE_PATH,
    MIN_REVOCATION_TTL,
    PATH_REQ_TOUT,
)
from lib.errors import SCIONBaseError
from lib.log import add_formatter, Rfc3339Formatter
from lib.path_seg_meta import PathSegMeta
from lib.packet.ctrl_pld import CtrlPayload, mk_ctrl_req_id
from lib.packet.path_mgmt.base import PathMgmt
from lib.packet.path_mgmt.ifstate import IFStatePayload
from lib.packet.path_mgmt.rev_info import RevocationInfo, SignedRevInfo
from lib.packet.path_mgmt.seg_req import PathSegmentReply
from lib.packet.path_mgmt.seg_recs import PathSegmentRecords
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.packet.svc import SVCType
from lib.path_db import DBResult, PathSegmentDB
from lib.rev_cache import RevCache
from lib.thread import thread_safety_net
from lib.types import (
    CertMgmtType,
    LinkType,
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
    ServiceType,
)
from lib.util import SCIONTime, sleep_interval
from lib.zk.cache import ZkSharedCache
from lib.zk.errors import ZkNoConnection
from lib.zk.id import ZkID
from lib.zk.zk import ZK_LOCK_SUCCESS, Zookeeper
from scion_elem.scion_elem import SCIONElement


# Exported metrics.
REQS_TOTAL = Counter("ps_reqs_total", "# of path requests", ["server_id", "isd_as"])
REQS_PENDING = Gauge("ps_req_pending_total", "# of pending path requests", ["server_id", "isd_as"])
SEGS_TO_ZK = Gauge("ps_segs_to_zk_total", "# of path segments to ZK", ["server_id", "isd_as"])
REVS_TO_ZK = Gauge("ps_revs_to_zk_total", "# of revocations to ZK", ["server_id", "isd_as"])
IS_MASTER = Gauge("ps_is_master", "true if this process is the replication master",
                  ["server_id", "isd_as"])


class PathServer(SCIONElement, metaclass=ABCMeta):
    """
    The SCION Path Server.
    """
    SERVICE_TYPE = ServiceType.PS
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
    ZK_REV_OBJ_MAX_AGE = MIN_REVOCATION_TTL
    # TTL of segments in the queue for ZK (in seconds)
    SEGS_TO_ZK_TTL = 10 * 60

    def __init__(self, server_id, conf_dir, spki_cache_dir=GEN_CACHE_PATH,
                 prom_export=None, sciond_path=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        :param str sciond_path: path to sciond socket.
        """
        super().__init__(server_id, conf_dir, spki_cache_dir=spki_cache_dir,
                         prom_export=prom_export, sciond_path=sciond_path)
        self.config = self._load_as_conf()
        down_labels = {**self._labels, "type": "down"} if self._labels else None
        core_labels = {**self._labels, "type": "core"} if self._labels else None
        self.down_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO, labels=down_labels)
        self.core_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO, labels=core_labels)
        # Dict of pending requests.
        self.pending_req = defaultdict(lambda: ExpiringDict(1000, PATH_REQ_TOUT))
        self.pen_req_lock = threading.Lock()
        self._request_logger = None
        # Used when l/cPS doesn't have up/dw-path.
        self.waiting_targets = defaultdict(list)
        self.revocations = RevCache(labels=self._labels)
        # Used to serialize removal of revoked segments
        self.seglock = Lock()
        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.IFSTATE_INFOS: self.handle_ifstate_infos,
                PMT.REQUEST: self.path_resolution,
                PMT.REPLY: self.handle_path_reply,
                PMT.REG: self.handle_seg_recs,
                PMT.REVOCATION: self._handle_revocation,
                PMT.SYNC: self.handle_seg_recs,
            },
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REQ: self.process_cert_chain_request,
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_reply,
                CertMgmtType.TRC_REPLY: self.process_trc_reply,
                CertMgmtType.TRC_REQ: self.process_trc_request,
            },
        }
        self.SCMP_PLD_CLASS_MAP = {
            SCMPClass.PATH: {
                SCMPPathClass.REVOKED_IF: self._handle_scmp_revocation,
            },
        }
        self._segs_to_zk = ExpiringDict(1000, self.SEGS_TO_ZK_TTL)
        self._revs_to_zk = ExpiringDict(1000, MIN_REVOCATION_TTL)
        self._zkid = ZkID.from_values(self.addr.isd_as, self.id,
                                      [(self.addr.host, self._port)])
        self.zk = Zookeeper(self.topology.isd_as, self.SERVICE_TYPE,
                            self._zkid.copy().pack(), self.topology.zookeepers)
        self.zk.retry("Joining party", self.zk.party_setup)
        self.path_cache = ZkSharedCache(self.zk, self.ZK_PATH_CACHE_PATH,
                                        self._handle_paths_from_zk)
        self.rev_cache = ZkSharedCache(self.zk, self.ZK_REV_CACHE_PATH,
                                       self._rev_entries_handler)
        self._init_request_logger()

    def worker(self):
        """
        Worker thread that takes care of reading shared paths from ZK, and
        handling master election for core servers.
        """
        worker_cycle = 1.0
        start = SCIONTime.get_time()
        while self.run_flag.is_set():
            sleep_interval(start, worker_cycle, "cPS.worker cycle",
                           self._quiet_startup())
            start = SCIONTime.get_time()
            try:
                self.zk.wait_connected()
                self.path_cache.process()
                self.rev_cache.process()
                # Try to become a master.
                ret = self.zk.get_lock(lock_timeout=0, conn_timeout=0)
                if ret:  # Either got the lock, or already had it.
                    if ret == ZK_LOCK_SUCCESS:
                        logging.info("Became master")
                    self.path_cache.expire(self.config.propagation_time * 10)
                    self.rev_cache.expire(self.ZK_REV_OBJ_MAX_AGE)
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')
                pass
            self._update_master()
            self._propagate_and_sync()
            self._handle_pending_requests()
            self._update_metrics()

    def _update_master(self):
        pass

    def _rev_entries_handler(self, raw_entries):
        for raw in raw_entries:
            srev_info = SignedRevInfo.from_raw(raw)
            rev_info = srev_info.rev_info()
            self.check_revocation(srev_info, lambda x:
                                  self._remove_revoked_segments(rev_info) if not x else False)

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
            logging.info("%s-Segment registered: %s", name, pcb.short_id())
            return True
        elif res == DBResult.ENTRY_UPDATED:
            logging.debug("%s-Segment updated: %s", name, pcb.short_id())
        return False

    def handle_ifstate_infos(self, cpld, meta):
        """
        Handles IFStateInfos.

        :param IFStatePayload infos: The state info objects.
        """
        pmgt = cpld.union
        infos = pmgt.union
        assert isinstance(infos, IFStatePayload), type(infos)
        for info in infos.iter_infos():
            if not info.p.active and info.p.sRevInfo:
                self._handle_revocation(CtrlPayload(PathMgmt(info.srev_info())), meta)

    def _handle_scmp_revocation(self, pld, meta):
        srev_info = SignedRevInfo.from_raw(pld.info.srev_info)
        self._handle_revocation(CtrlPayload(PathMgmt(srev_info)), meta)

    def _handle_revocation(self, cpld, meta):
        """
        Handles a revocation of a segment, interface or hop.
        :param rev_info: The RevocationInfo object.
        """
        pmgt = cpld.union
        srev_info = pmgt.union
        rev_info = srev_info.rev_info()
        assert isinstance(rev_info, RevocationInfo), type(rev_info)
        # Validate before checking for presence in self.revocations, as that will trigger an assert
        # failure if the rev_info is invalid.
        try:
            rev_info.validate()
        except SCIONBaseError as e:
            logging.error("Failed to validate RevInfo from %s: %s\n%s",
                          meta, e, rev_info.short_desc())
            return

        if srev_info in self.revocations:
            return
        logging.debug("Received revocation from %s: %s", meta, rev_info.short_desc())
        self.check_revocation(srev_info, lambda x: self._continue_revocation_processing(meta,
                              srev_info) if not x else False, meta)

    def _continue_revocation_processing(self, meta, srev_info):
        self.revocations.add(srev_info)
        self._revs_to_zk[srev_info] = srev_info.copy().pack()  # have to pack copy
        # Remove segments that contain the revoked interface.
        self._remove_revoked_segments(srev_info.rev_info())
        # Forward revocation to other path servers.
        self._forward_revocation(srev_info, meta)

    def _remove_revoked_segments(self, rev_info):
        """
        Loop through all segments and remove those containing a revoked IFID
        Make sure the revocation is checked beforehand
        :param rev_info: The revocation info
        :type rev_info: RevocationInfo
        """
        def _handle_one_seg(seg, db, core=False):
            rm, ltype = seg.rev_match(rev_info, core)
            if rm and (ltype in [LinkType.PARENT, LinkType.CHILD, LinkType.CORE] and
               db.delete(seg.get_hops_hash()) == DBResult.ENTRY_DELETED):
                return 1
            return 0

        up_segs_removed = 0
        down_segs_removed = 0
        core_segs_removed = 0
        with self.seglock:
            if not self.topology.is_core_as:
                for up_segment in self.up_segments(full=True):
                    up_segs_removed += _handle_one_seg(up_segment, self.up_segments)
            for down_segment in self.down_segments(full=True):
                down_segs_removed += _handle_one_seg(down_segment, self.down_segments)
            for core_segment in self.core_segments(full=True):
                core_segs_removed += _handle_one_seg(core_segment, self.core_segments, True)

        logging.debug("Removed segments revoked by [%s]: UP: %d DOWN: %d CORE: %d" %
                      (rev_info.short_desc(), up_segs_removed, down_segs_removed,
                       core_segs_removed))

    @abstractmethod
    def _forward_revocation(self, rev_info, meta):
        """
        Forwards a revocation to other path servers that need to be notified.

        :param rev_info: The RevInfo object.
        :param meta: The MessageMeta object.
        """
        raise NotImplementedError

    def _send_path_segments(self, req, req_id, meta, logger, up=None, core=None, down=None):
        """
        Sends path-segments to requester (depending on Path Server's location).
        """
        up = up or set()
        core = core or set()
        down = down or set()
        all_segs = up | core | down
        if not all_segs:
            logger.warning("No segments to send for request: %s from: %s" %
                           (req.short_desc(), meta))
            return
        srevs_to_add = self._peer_revs_for_segs(all_segs)
        recs = PathSegmentRecords.from_values(
            {PST.UP: up, PST.CORE: core, PST.DOWN: down},
            srevs_to_add
        )
        pld = PathSegmentReply.from_values(req.copy(), recs)
        self.send_meta(CtrlPayload(PathMgmt(pld), req_id=req_id), meta)
        logger.info("Sending PATH_REPLY with %d segment(s): %s", len(all_segs),
                    [seg.short_id() for seg in all_segs])

    def _peer_revs_for_segs(self, segs):
        """Returns a list of signed peer revocations for segments in 'segs'."""
        def _handle_one_seg(seg):
            for asm in seg.iter_asms():
                for pcbm in asm.iter_pcbms(1):
                    hof = pcbm.hof()
                    for if_id in [hof.ingress_if, hof.egress_if]:
                        srev_info = self.revocations.get((asm.isd_as(), if_id))
                        if srev_info:
                            srevs_to_add.add(srev_info.copy())
                            return
        srevs_to_add = set()
        for seg in segs:
            _handle_one_seg(seg)

        return list(srevs_to_add)

    def _handle_pending_requests(self):
        rem_keys = []
        # Serve pending requests.
        with self.pen_req_lock:
            for key in self.pending_req:
                for req_key, (req, req_id, meta, logger) in self.pending_req[key].items():
                    if self.path_resolution(CtrlPayload(PathMgmt(req), req_id=req_id), meta,
                                            new_request=False, logger=logger):
                        meta.close()
                        del self.pending_req[key][req_key]
                if not self.pending_req[key]:
                    rem_keys.append(key)
            for key in rem_keys:
                del self.pending_req[key]

    def _handle_paths_from_zk(self, raw_entries):
        """
        Handles cached paths through ZK, passed as a list.
        """
        for raw in raw_entries:
            recs = PathSegmentRecords.from_raw(raw)
            for type_, pcb in recs.iter_pcbs():
                seg_meta = PathSegMeta(pcb, self.continue_seg_processing,
                                       type_=type_, params={'from_zk': True})
                self._process_path_seg(seg_meta)
        if raw_entries:
            logging.debug("Processed %s segments from ZK", len(raw_entries))

    def handle_path_reply(self, cpld, meta):
        pmgt = cpld.union
        reply = pmgt.union
        assert isinstance(reply, PathSegmentReply), type(reply)
        self._handle_seg_recs(reply.recs(), cpld.req_id, meta)

    def handle_seg_recs(self, cpld, meta):
        pmgt = cpld.union
        seg_recs = pmgt.union
        self._handle_seg_recs(seg_recs, cpld.req_id, meta)

    def _handle_seg_recs(self, seg_recs, req_id, meta):
        """
        Handles paths received from the network.
        """
        assert isinstance(seg_recs, PathSegmentRecords), type(seg_recs)
        params = self._dispatch_params(seg_recs, meta)
        # Add revocations for peer interfaces included in the path segments.
        for srev_info in seg_recs.iter_srev_infos():
            self.revocations.add(srev_info)
        # Verify pcbs and process them
        for type_, pcb in seg_recs.iter_pcbs():
            seg_meta = PathSegMeta(pcb, self.continue_seg_processing, meta,
                                   type_, params)
            self._process_path_seg(seg_meta, req_id)

    def continue_seg_processing(self, seg_meta):
        """
        For every path segment(that can be verified) received from the network
        or ZK this function gets called to continue the processing for the
        segment.
        The segment is added to pathdb and pending requests are checked.
        """
        pcb = seg_meta.seg
        logging.debug("Successfully verified PCB %s" % pcb.short_id())
        type_ = seg_meta.type
        params = seg_meta.params
        self.handle_ext(pcb)
        self._dispatch_segment_record(type_, pcb, **params)
        self._handle_pending_requests()

    def handle_ext(self, pcb):
        """
        Handle beacon extensions.
        """
        # Handle PCB extensions:
        for asm in pcb.iter_asms():
            pol = asm.routing_pol_ext()
            if pol:
                self.handle_routing_pol_ext(pol)

    def handle_routing_pol_ext(self, ext):
        # TODO(Sezer): Implement extension handling
        logging.debug("Routing policy extension: %s" % ext)

    def _dispatch_segment_record(self, type_, seg, **kwargs):
        # Check that segment does not contain a revoked interface.
        if not self.check_revoked_interface(seg, self.revocations):
            return
        handle_map = {
            PST.UP: self._handle_up_segment_record,
            PST.CORE: self._handle_core_segment_record,
            PST.DOWN: self._handle_down_segment_record,
        }
        with self.seglock:
            handle_map[type_](seg, **kwargs)

    def _dispatch_params(self, pld, meta):
        return {}

    def _propagate_and_sync(self):
        self._share_via_zk()
        self._share_revs_via_zk()

    def _gen_prop_recs(self, container, limit=PROP_LIMIT):
        count = 0
        pcbs = defaultdict(list)
        while container:
            try:
                _, (type_, pcb) = container.popitem(last=False)
            except KeyError:
                continue
            count += 1
            pcbs[type_].append(pcb.copy())
            if count >= limit:
                yield(pcbs)
                count = 0
                pcbs = defaultdict(list)
        if pcbs:
            yield(pcbs)

    @abstractmethod
    def path_resolution(self, path_request, meta, new_request=True, logger=None):
        """
        Handles all types of path request.
        """
        raise NotImplementedError

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
            (seg_req, logger) = targets.pop(0)
            meta = self._build_meta(ia=src_ia, path=path, host=SVCType.PS_A, reuse=True)
            req_id = mk_ctrl_req_id()
            self.send_meta(CtrlPayload(PathMgmt(seg_req), req_id=req_id), meta)
            logger.info("Waiting request (%s) sent to %s via %s [id: %016x]",
                        seg_req.short_desc(), meta, pcb.short_desc(), req_id)

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
            try:
                data = self._revs_to_zk.popitem(last=False)[1]
            except KeyError:
                continue
            self._zk_write_rev(data)

    def _zk_write(self, data):
        hash_ = crypto_hash(data).hex()
        try:
            self.path_cache.store("%s-%s" % (hash_, SCIONTime.get_time()), data)
        except ZkNoConnection:
            logging.warning("Unable to store segment(s) in shared path: "
                            "no connection to ZK")

    def _zk_write_rev(self, data):
        hash_ = crypto_hash(data).hex()
        try:
            self.rev_cache.store("%s-%s" % (hash_, SCIONTime.get_time()), data)
        except ZkNoConnection:
            logging.warning("Unable to store revocation(s) in shared path: "
                            "no connection to ZK")

    def _init_request_logger(self):
        """
        Initializes the request logger.
        """
        self._request_logger = logging.getLogger("RequestLogger")
        # Create new formatter to include the request in the log.
        formatter = formatter = Rfc3339Formatter(
            "%(asctime)s [%(levelname)s] (%(threadName)s) %(message)s "
            "{id=%(id)s, from=%(from)s}")
        add_formatter('RequestLogger', formatter)

    def get_request_logger(self, req_id, meta):
        """
        Returns a logger adapter for a request.
        """
        # Create a logger for the request to log with context.
        return logging.LoggerAdapter(
            self._request_logger,
            {"id": req_id, "from": str(meta)})

    def _init_metrics(self):
        super()._init_metrics()
        REQS_TOTAL.labels(**self._labels).inc(0)
        REQS_PENDING.labels(**self._labels).set(0)
        SEGS_TO_ZK.labels(**self._labels).set(0)
        REVS_TO_ZK.labels(**self._labels).set(0)
        IS_MASTER.labels(**self._labels).set(0)

    def _update_metrics(self):
        """
        Updates all Gauge metrics. Subclass can update their own metrics but must
        call the superclass' implementation.
        """
        if not self._labels:
            return
        # Update pending requests metric.
        # XXX(shitz): This could become a performance problem should there ever be
        # a large amount of pending requests (>100'000).
        total_pending = 0
        with self.pen_req_lock:
            for reqs in self.pending_req.values():
                total_pending += len(reqs)
        REQS_PENDING.labels(**self._labels).set(total_pending)
        # Update SEGS_TO_ZK and REVS_TO_ZK metrics.
        SEGS_TO_ZK.labels(**self._labels).set(len(self._segs_to_zk))
        REVS_TO_ZK.labels(**self._labels).set(len(self._revs_to_zk))
        # Update IS_MASTER metric.
        IS_MASTER.labels(**self._labels).set(int(self.zk.have_lock()))

    def run(self):
        """
        Run an instance of the Path Server.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="PS.worker", daemon=True).start()
        threading.Thread(
            target=thread_safety_net, args=(self._check_trc_cert_reqs,),
            name="Elem.check_trc_cert_reqs", daemon=True).start()
        super().run()
