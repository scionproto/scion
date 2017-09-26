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
:mod:`sciond` --- Reference endhost SCION Daemon
================================================
"""
# Stdlib
import logging
import os
import threading
from itertools import product

# External
from external.expiring_dict import ExpiringDict

# SCION
from lib.crypto.hash_tree import ConnectedHashTree
from lib.defines import (
    PATH_FLAG_SIBRA,
    PATH_REQ_TOUT,
    PATH_SERVICE,
    SCIOND_API_SOCKDIR,
)
from lib.errors import SCIONParseError, SCIONServiceLookupError
from lib.log import log_exception
from lib.msg_meta import SockOnlyMetadata
from lib.path_seg_meta import PathSegMeta
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.path import SCIONPath
from lib.packet.path_mgmt.base import PathMgmt
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.path_mgmt.seg_req import PathSegmentReq
from lib.packet.path_mgmt.seg_recs import PathSegmentRecords
from lib.packet.scion_addr import ISD_AS
from lib.packet.scmp.types import SCMPClass, SCMPPathClass
from lib.path_combinator import build_shortcut_paths, tuples_to_full_paths
from lib.path_db import DBResult, PathSegmentDB
from lib.rev_cache import RevCache
from lib.sciond_api.as_req import SCIONDASInfoReply, SCIONDASInfoReplyEntry, SCIONDASInfoRequest
from lib.sciond_api.revocation import SCIONDRevReply, SCIONDRevReplyStatus
from lib.sciond_api.host_info import HostInfo
from lib.sciond_api.if_req import SCIONDIFInfoReply, SCIONDIFInfoReplyEntry, SCIONDIFInfoRequest
from lib.sciond_api.base import SCIONDMsg
from lib.sciond_api.path_meta import FwdPathMeta
from lib.sciond_api.path_req import (
    SCIONDPathRequest,
    SCIONDPathReplyError,
    SCIONDPathReply,
    SCIONDPathReplyEntry,
)
from lib.sciond_api.revocation import SCIONDRevNotification
from lib.sciond_api.service_req import (
    SCIONDServiceInfoReply,
    SCIONDServiceInfoReplyEntry,
    SCIONDServiceInfoRequest,
)
from lib.sibra.ext.resv import ResvBlockSteady
from lib.socket import ReliableSocket
from lib.thread import thread_safety_net
from lib.types import (
    CertMgmtType,
    PathMgmtType as PMT,
    PathSegmentType as PST,
    PayloadClass,
    SCIONDMsgType as SMT,
    ServiceType,
    TypeBase,
)
from lib.util import SCIONTime
from scion_elem.scion_elem import SCIONElement


_FLUSH_FLAG = "FLUSH"


class SCIONDaemon(SCIONElement):
    """
    The SCION Daemon used for retrieving and combining paths.
    """
    MAX_REQS = 1024
    # Time a path segment is cached at a host (in seconds).
    SEGMENT_TTL = 300

    def __init__(self, conf_dir, addr, api_addr, run_local_api=False,
                 port=None, prom_export=None):
        """
        Initialize an instance of the class SCIONDaemon.
        """
        super().__init__("sciond", conf_dir, prom_export=prom_export, public=[(addr, port)])
        up_labels = {**self._labels, "type": "up"} if self._labels else None
        down_labels = {**self._labels, "type": "down"} if self._labels else None
        core_labels = {**self._labels, "type": "core"} if self._labels else None
        self.up_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL, labels=up_labels)
        self.down_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL, labels=down_labels)
        self.core_segments = PathSegmentDB(segment_ttl=self.SEGMENT_TTL, labels=core_labels)
        self.peer_revs = RevCache()
        # Keep track of requested paths.
        self.requested_paths = ExpiringDict(self.MAX_REQS, PATH_REQ_TOUT)
        self.req_path_lock = threading.Lock()
        self._api_sock = None
        self.daemon_thread = None
        os.makedirs(SCIOND_API_SOCKDIR, exist_ok=True)
        self.api_addr = (api_addr or
                         os.path.join(SCIOND_API_SOCKDIR,
                                      "%s.sock" % self.addr.isd_as))

        self.CTRL_PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REPLY: self.handle_path_reply,
                PMT.REVOCATION: self.handle_revocation,
            },
            PayloadClass.CERT: {
                CertMgmtType.CERT_CHAIN_REQ: self.process_cert_chain_request,
                CertMgmtType.CERT_CHAIN_REPLY: self.process_cert_chain_reply,
                CertMgmtType.TRC_REPLY: self.process_trc_reply,
                CertMgmtType.TRC_REQ: self.process_trc_request,
            },
        }

        self.SCMP_PLD_CLASS_MAP = {
            SCMPClass.PATH:
                {SCMPPathClass.REVOKED_IF: self.handle_scmp_revocation},
        }

        if run_local_api:
            self._api_sock = ReliableSocket(bind_unix=(self.api_addr, "sciond"))
            self._socks.add(self._api_sock, self.handle_accept)

    @classmethod
    def start(cls, conf_dir, addr, api_addr=None, run_local_api=False, port=0):
        """
        Initializes, starts, and returns a SCIONDaemon object.

        Example of usage:
        sd = SCIONDaemon.start(conf_dir, addr)
        paths = sd.get_paths(isd_as)
        """
        inst = cls(conf_dir, addr, api_addr, run_local_api, port)
        name = "SCIONDaemon.run %s" % inst.addr.isd_as
        inst.daemon_thread = threading.Thread(
            target=thread_safety_net, args=(inst.run,), name=name, daemon=True)
        inst.daemon_thread.start()
        logging.debug("sciond started with api_addr = %s", inst.api_addr)
        return inst

    def _get_msg_meta(self, packet, addr, sock):
        if sock != self._udp_sock:
            return packet, SockOnlyMetadata.from_values(sock)  # API socket
        else:
            return super()._get_msg_meta(packet, addr, sock)

    def handle_msg_meta(self, msg, meta):
        """
        Main routine to handle incoming SCION messages.
        """
        if isinstance(meta, SockOnlyMetadata):  # From SCIOND API
            try:
                sciond_msg = SCIONDMsg.from_raw(msg)
            except SCIONParseError as err:
                logging.error(str(err))
                return
            self.api_handle_request(sciond_msg, meta)
            return
        super().handle_msg_meta(msg, meta)

    def handle_path_reply(self, cpld, meta):
        """
        Handle path reply from local path server.
        """
        pmgt = cpld.contents
        path_reply = pmgt.contents
        assert isinstance(path_reply, PathSegmentRecords), type(path_reply)
        for rev_info in path_reply.iter_rev_infos():
            self.peer_revs.add(rev_info)

        for type_, pcb in path_reply.iter_pcbs():
            seg_meta = PathSegMeta(pcb, self.continue_seg_processing,
                                   meta, type_)
            self._process_path_seg(seg_meta)

    def continue_seg_processing(self, seg_meta):
        """
        For every path segment(that can be verified) received from the path
        server this function gets called to continue the processing for the
        segment.
        The segment is added to pathdb and pending requests are checked.
        """
        pcb = seg_meta.seg
        type_ = seg_meta.type
        map_ = {
            PST.UP: self._handle_up_seg,
            PST.DOWN: self._handle_down_seg,
            PST.CORE: self._handle_core_seg,
        }
        ret = map_[type_](pcb)
        if not ret:
            return
        with self.req_path_lock:
            # .items() makes a copy on an expiring dict, so deleting entries is safe.
            for key, e in self.requested_paths.items():
                if self.path_resolution(*key):
                    e.set()
                    del self.requested_paths[key]

    def _handle_up_seg(self, pcb):
        if self.addr.isd_as != pcb.last_ia():
            return None
        if self.up_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Up segment added: %s", pcb.short_desc())
            return pcb.first_ia()
        return None

    def _handle_down_seg(self, pcb):
        last_ia = pcb.last_ia()
        if self.addr.isd_as == last_ia:
            return None
        if self.down_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Down segment added: %s", pcb.short_desc())
            return last_ia
        return None

    def _handle_core_seg(self, pcb):
        if self.core_segments.update(pcb) == DBResult.ENTRY_ADDED:
            logging.debug("Core segment added: %s", pcb.short_desc())
            return pcb.first_ia()
        return None

    def api_handle_request(self, msg, meta):
        """
        Handle local API's requests.
        """
        mtype = msg.type()
        if mtype == SMT.PATH_REQUEST:
            threading.Thread(
                target=thread_safety_net,
                args=(self._api_handle_path_request, msg, meta),
                daemon=True).start()
        elif mtype == SMT.REVOCATION:
            self._api_handle_rev_notification(msg, meta)
        elif mtype == SMT.AS_REQUEST:
            self._api_handle_as_request(msg, meta)
        elif mtype == SMT.IF_REQUEST:
            self._api_handle_if_request(msg, meta)
        elif mtype == SMT.SERVICE_REQUEST:
            self._api_handle_service_request(msg, meta)
        else:
            logging.warning(
                "API: type %s not supported.", TypeBase.to_str(mtype))

    def _api_handle_path_request(self, pld, meta):
        request = pld.contents
        assert isinstance(request, SCIONDPathRequest), type(request)
        req_id = pld.id
        if request.p.flags.sibra:
            logging.warning(
                "Requesting SIBRA paths over SCIOND API not supported yet.")
            self._send_path_reply(
                req_id, [], SCIONDPathReplyError.INTERNAL, meta)
            return

        dst_ia = request.dst_ia()
        src_ia = request.src_ia()
        if not src_ia:
            src_ia = self.addr.isd_as
        thread = threading.current_thread()
        thread.name = "SCIONDaemon API id:%s %s -> %s" % (
            thread.ident, src_ia, dst_ia)
        paths, error = self.get_paths(dst_ia, flush=request.p.flags.flush)
        if request.p.maxPaths:
            paths = paths[:request.p.maxPaths]
        logging.debug("Replying to api request for %s with %d paths",
                      dst_ia, len(paths))
        reply_entries = []
        for path_meta in paths:
            fwd_if = path_meta.fwd_path().get_fwd_if()
            # Set dummy host addr if path is empty.
            haddr, port = None, None
            if fwd_if:
                br = self.ifid2br[fwd_if]
                addr_idx = br.interfaces[fwd_if].addr_idx
                haddr, port = br.int_addrs[addr_idx].public[0]
            addrs = [haddr] if haddr else []
            first_hop = HostInfo.from_values(addrs, port)
            reply_entry = SCIONDPathReplyEntry.from_values(
                path_meta, first_hop)
            reply_entries.append(reply_entry)
        self._send_path_reply(req_id, reply_entries, error, meta)

    def _send_path_reply(self, req_id, reply_entries, error, meta):
        path_reply = SCIONDMsg(SCIONDPathReply.from_values(reply_entries, error), req_id)
        self.send_meta(path_reply.pack(), meta)

    def _api_handle_as_request(self, pld, meta):
        request = pld.contents
        assert isinstance(request, SCIONDASInfoRequest), type(request)
        remote_as = request.isd_as()
        if remote_as:
            reply_entry = SCIONDASInfoReplyEntry.from_values(
                remote_as, self.is_core_as(remote_as))
        else:
            reply_entry = SCIONDASInfoReplyEntry.from_values(
                self.addr.isd_as, self.is_core_as(), self.topology.mtu)
        as_reply = SCIONDMsg(SCIONDASInfoReply.from_values([reply_entry]), pld.id)
        self.send_meta(as_reply.pack(), meta)

    def _api_handle_if_request(self, pld, meta):
        request = pld.contents
        assert isinstance(request, SCIONDIFInfoRequest), type(request)
        all_brs = request.all_brs()
        if_list = []
        if not all_brs:
            if_list = list(request.iter_ids())
        if_entries = []
        for if_id, br in self.ifid2br.items():
            if all_brs or if_id in if_list:
                addr_idx = br.interfaces[if_id].addr_idx
                br_addr, br_port = br.int_addrs[addr_idx].public[0]
                info = HostInfo.from_values([br_addr], br_port)
                reply_entry = SCIONDIFInfoReplyEntry.from_values(if_id, info)
                if_entries.append(reply_entry)
        if_reply = SCIONDMsg(SCIONDIFInfoReply.from_values(if_entries), pld.id)
        self.send_meta(if_reply.pack(), meta)

    def _api_handle_service_request(self, pld, meta):
        request = pld.contents
        assert isinstance(request, SCIONDServiceInfoRequest), type(request)
        all_svcs = request.all_services()
        svc_list = []
        if not all_svcs:
            svc_list = list(request.iter_service_types())
        svc_entries = []
        for svc_type in ServiceType.all():
            if all_svcs or svc_type in svc_list:
                lookup_res = self.dns_query_topo(svc_type)
                host_infos = []
                for addr, port in lookup_res:
                    host_infos.append(HostInfo.from_values([addr], port))
                reply_entry = SCIONDServiceInfoReplyEntry.from_values(
                    svc_type, host_infos)
                svc_entries.append(reply_entry)
        svc_reply = SCIONDMsg(SCIONDServiceInfoReply.from_values(svc_entries), pld.id)
        self.send_meta(svc_reply.pack(), meta)

    def _api_handle_rev_notification(self, pld, meta):
        request = pld.contents
        assert isinstance(request, SCIONDRevNotification), type(request)
        status = self.handle_revocation(CtrlPayload(PathMgmt(request.rev_info())), meta)
        rev_reply = SCIONDMsg(SCIONDRevReply.from_values(status), pld.id)
        self.send_meta(rev_reply.pack(), meta)

    def handle_scmp_revocation(self, pld, meta):
        rev_info = RevocationInfo.from_raw(pld.info.rev_info)
        self.handle_revocation(CtrlPayload(PathMgmt(rev_info)), meta)

    def handle_revocation(self, cpld, meta):
        pmgt = cpld.contents
        rev_info = pmgt.contents
        assert isinstance(rev_info, RevocationInfo), type(rev_info)
        if not self._validate_revocation(rev_info):
            return SCIONDRevReplyStatus.INVALID
        logging.debug("Revocation info received: %s", rev_info)

        # Verify epoch information and on failure return directly
        epoch_status = ConnectedHashTree.verify_epoch(rev_info.p.epoch)
        if epoch_status == ConnectedHashTree.EPOCH_PAST:
            logging.error(
                "Failed to verify epoch: epoch in the past %d,current epoch %d."
                % (rev_info.p.epoch, ConnectedHashTree.get_current_epoch()))
            return SCIONDRevReplyStatus.INVALID

        if epoch_status == ConnectedHashTree.EPOCH_FUTURE:
            logging.warning(
                "Failed to verify epoch: epoch in the future %d,current epoch %d."
                % (rev_info.p.epoch, ConnectedHashTree.get_current_epoch()))
            return SCIONDRevReplyStatus.INVALID

        if epoch_status == ConnectedHashTree.EPOCH_NEAR_PAST:
            logging.info(
                "Failed to verify epoch: epoch in the near past %d, current epoch %d."
                % (rev_info.p.epoch, ConnectedHashTree.get_current_epoch()))
            return SCIONDRevReplyStatus.STALE

        # Go through all segment databases and remove affected segments.
        removed_up = self._remove_revoked_pcbs(self.up_segments, rev_info)
        removed_core = self._remove_revoked_pcbs(self.core_segments, rev_info)
        removed_down = self._remove_revoked_pcbs(self.down_segments, rev_info)
        logging.info("Removed %d UP- %d CORE- and %d DOWN-Segments." %
                     (removed_up, removed_core, removed_down))
        total = removed_up + removed_core + removed_down
        if total > 0:
            return SCIONDRevReplyStatus.VALID
        else:
            # FIXME(scrye): UNKNOWN is returned in the following situations:
            #  - No matching segments exist
            #  - Matching segments exist, but the revoked interface is part of
            #  a peering link; new path queries sent to SCIOND won't use the
            #  link, but nothing is immediately revoked
            #  - A hash check failed and prevented the revocation from taking
            #  place
            #
            # This should be fixed in the future to provide clearer meaning
            # behind why the revocation could not be validated.
            #
            # For now, if applications receive an UNKOWN reply to a revocation,
            # they should strongly consider flushing paths containing the
            # interface.
            return SCIONDRevReplyStatus.UNKNOWN

    def _remove_revoked_pcbs(self, db, rev_info):
        """
        Removes all segments from 'db' that contain an IF token for which
        rev_token is a preimage (within 20 calls).

        :param db: The PathSegmentDB.
        :type db: :class:`lib.path_db.PathSegmentDB`
        :param rev_info: The revocation info
        :type rev_info: RevocationInfo

        :returns: The number of deletions.
        :rtype: int
        """

        to_remove = []
        for segment in db(full=True):
            for asm in segment.iter_asms():
                if self._verify_revocation_for_asm(rev_info, asm):
                    logging.debug("Removing segment: %s" % segment.short_desc())
                    to_remove.append(segment.get_hops_hash())
        return db.delete_all(to_remove)

    def _flush_path_dbs(self):
        self.core_segments.flush()
        self.down_segments.flush()
        self.up_segments.flush()

    def get_paths(self, dst_ia, flags=(), flush=False):
        """Return a list of paths."""
        logging.debug("Paths requested for ISDAS=%s, flags=%s, flush=%s",
                      dst_ia, flags, flush)
        if flush:
            logging.info("Flushing PathDBs.")
            self._flush_path_dbs()
        if self.addr.isd_as == dst_ia or (
                self.addr.isd_as.any_as() == dst_ia and
                self.topology.is_core_as):
            # Either the destination is the local AS, or the destination is any
            # core AS in this ISD, and the local AS is in the core
            empty = SCIONPath()
            empty_meta = FwdPathMeta.from_values(empty, [], self.topology.mtu)
            return [empty_meta], SCIONDPathReplyError.OK
        paths = self.path_resolution(dst_ia, flags=flags)
        if not paths:
            key = dst_ia, flags
            with self.req_path_lock:
                if key not in self.requested_paths:
                    # No previous outstanding request
                    self.requested_paths[key] = threading.Event()
                    self._fetch_segments(key)
                e = self.requested_paths[key]
            if not e.wait(PATH_REQ_TOUT):
                logging.error("Query timed out for %s", dst_ia)
                return [], SCIONDPathReplyError.PS_TIMEOUT
            paths = self.path_resolution(dst_ia, flags=flags)
        error_code = (SCIONDPathReplyError.OK if paths
                      else SCIONDPathReplyError.NO_PATHS)
        return paths, error_code

    def path_resolution(self, dst_ia, flags=()):
        # dst as == 0 means any core AS in the specified ISD.
        dst_is_core = self.is_core_as(dst_ia) or dst_ia[1] == 0
        sibra = PATH_FLAG_SIBRA in flags
        if self.topology.is_core_as:
            if dst_is_core:
                ret = self._resolve_core_core(dst_ia, sibra=sibra)
            else:
                ret = self._resolve_core_not_core(dst_ia, sibra=sibra)
        elif dst_is_core:
            ret = self._resolve_not_core_core(dst_ia, sibra=sibra)
        elif sibra:
            ret = self._resolve_not_core_not_core_sibra(dst_ia)
        else:
            ret = self._resolve_not_core_not_core_scion(dst_ia)
        if not sibra:
            return ret
        # FIXME(kormat): Strip off PCBs, and just return sibra reservation
        # blocks
        return self._sibra_strip_pcbs(self._strip_nones(ret))

    def _resolve_core_core(self, dst_ia, sibra=False):
        """Resolve path from core to core."""
        res = set()
        for cseg in self.core_segments(last_ia=self.addr.isd_as, sibra=sibra,
                                       **dst_ia.params()):
                res.add((None, cseg, None))
        if sibra:
            return res
        return tuples_to_full_paths(res)

    def _resolve_core_not_core(self, dst_ia, sibra=False):
        """Resolve path from core to non-core."""
        res = set()
        # First check whether there is a direct path.
        for dseg in self.down_segments(
                first_ia=self.addr.isd_as, last_ia=dst_ia, sibra=sibra):
                res.add((None, None, dseg))
        # Check core-down combination.
        for dseg in self.down_segments(last_ia=dst_ia, sibra=sibra):
            dseg_ia = dseg.first_ia()
            if self.addr.isd_as == dseg_ia:
                pass
            for cseg in self.core_segments(
                    first_ia=dseg_ia, last_ia=self.addr.isd_as, sibra=sibra):
                res.add((None, cseg, dseg))
        if sibra:
            return res
        return tuples_to_full_paths(res)

    def _resolve_not_core_core(self, dst_ia, sibra=False):
        """Resolve path from non-core to core."""
        res = set()
        params = dst_ia.params()
        params["sibra"] = sibra
        if dst_ia[0] == self.addr.isd_as[0]:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            for useg in self.up_segments(**params):
                res.add((useg, None, None))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(**params):
            # Check do we have an up-seg that is connected to core_seg.
            for useg in self.up_segments(first_ia=cseg.last_ia(), sibra=sibra):
                res.add((useg, cseg, None))
        if sibra:
            return res
        return tuples_to_full_paths(res)

    def _resolve_not_core_not_core_scion(self, dst_ia):
        """Resolve SCION path from non-core to non-core."""
        up_segs = self.up_segments()
        down_segs = self.down_segments(last_ia=dst_ia)
        core_segs = self._calc_core_segs(dst_ia[0], up_segs, down_segs)
        full_paths = build_shortcut_paths(
            up_segs, down_segs, self.peer_revs)
        tuples = []
        for up_seg in up_segs:
            for down_seg in down_segs:
                tuples.append((up_seg, None, down_seg))
                for core_seg in core_segs:
                    tuples.append((up_seg, core_seg, down_seg))
        full_paths.extend(tuples_to_full_paths(tuples))
        return full_paths

    def _resolve_not_core_not_core_sibra(self, dst_ia):
        """Resolve SIBRA path from non-core to non-core."""
        res = set()
        up_segs = set(self.up_segments(sibra=True))
        down_segs = set(self.down_segments(last_ia=dst_ia, sibra=True))
        for up_seg, down_seg in product(up_segs, down_segs):
            src_core_ia = up_seg.first_ia()
            dst_core_ia = down_seg.first_ia()
            if src_core_ia == dst_core_ia:
                res.add((up_seg, down_seg))
                continue
            for core_seg in self.core_segments(first_ia=dst_core_ia,
                                               last_ia=src_core_ia, sibra=True):
                res.add((up_seg, core_seg, down_seg))
        return res

    def _strip_nones(self, set_):
        """Strip None entries from a set of tuples"""
        res = []
        for tup in set_:
            res.append(tuple(filter(None, tup)))
        return res

    def _sibra_strip_pcbs(self, paths):
        ret = []
        for pcbs in paths:
            resvs = []
            for pcb in pcbs:
                resvs.append(self._sibra_strip_pcb(pcb))
            ret.append(resvs)
        return ret

    def _sibra_strip_pcb(self, pcb):
        assert pcb.is_sibra()
        pcb_ext = pcb.sibra_ext
        resv_info = pcb_ext.info
        resv = ResvBlockSteady.from_values(resv_info, pcb.get_n_hops())
        asms = pcb.iter_asms()
        if pcb_ext.p.up:
            asms = reversed(list(asms))
        iflist = []
        for sof, asm in zip(pcb_ext.iter_sofs(), asms):
            resv.sofs.append(sof)
            iflist.extend(self._sibra_add_ifs(
                asm.isd_as(), sof, resv_info.fwd_dir))
        assert resv.num_hops == len(resv.sofs)
        return pcb_ext.p.id, resv, iflist

    def _sibra_add_ifs(self, isd_as, sof, fwd):
        def _add(ifid):
            if ifid:
                ret.append((isd_as, ifid))
        ret = []
        if fwd:
            _add(sof.ingress)
            _add(sof.egress)
        else:
            _add(sof.egress)
            _add(sof.ingress)
        return ret

    def _wait_for_events(self, events, deadline):
        """
        Wait on a set of events, but only until the specified deadline. Returns
        the number of events that happened while waiting.
        """
        count = 0
        for e in events:
            if e.wait(max(0, deadline - SCIONTime.get_time())):
                count += 1
        return count

    def _fetch_segments(self, key):
        """
        Called to fetch the requested path.
        """
        dst_ia, flags = key
        try:
            addr, port = self.dns_query_topo(PATH_SERVICE)[0]
        except SCIONServiceLookupError:
            log_exception("Error querying path service:")
            return
        req = PathSegmentReq.from_values(self.addr.isd_as, dst_ia, flags=flags)
        logging.debug("Sending path request (%s) to [%s]:%s", req.short_desc(), addr, port)
        meta = self._build_meta(host=addr, port=port)
        self.send_meta(CtrlPayload(PathMgmt(req)), meta)

    def _calc_core_segs(self, dst_isd, up_segs, down_segs):
        """
        Calculate all possible core segments joining the provided up and down
        segments. Returns a list of all known segments, and a seperate list of
        the missing AS pairs.
        """
        src_core_ases = set()
        dst_core_ases = set()
        for seg in up_segs:
            src_core_ases.add(seg.first_ia()[1])
        for seg in down_segs:
            dst_core_ases.add(seg.first_ia()[1])
        # Generate all possible AS pairs
        as_pairs = list(product(src_core_ases, dst_core_ases))
        return self._find_core_segs(self.addr.isd_as[0], dst_isd, as_pairs)

    def _find_core_segs(self, src_isd, dst_isd, as_pairs):
        """
        Given a set of AS pairs across 2 ISDs, return the core segments
        connecting those pairs
        """
        core_segs = []
        for src_core_as, dst_core_as in as_pairs:
            src_ia = ISD_AS.from_values(src_isd, src_core_as)
            dst_ia = ISD_AS.from_values(dst_isd, dst_core_as)
            if src_ia == dst_ia:
                continue
            seg = self.core_segments(first_ia=dst_ia, last_ia=src_ia)
            if seg:
                core_segs.extend(seg)
        return core_segs

    def run(self):
        """
        Run an instance of the SCION daemon.
        """
        threading.Thread(
            target=thread_safety_net, args=(self._check_trc_cert_reqs,),
            name="Elem.check_trc_cert_reqs", daemon=True).start()
        super().run()
