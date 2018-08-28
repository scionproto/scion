# Copyright 2014 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
:mod:`local` --- Local path server
==================================
"""
# Stdlib
import logging
from collections import defaultdict

# SCION
from lib.defines import GEN_CACHE_PATH
from lib.packet.svc import SVCType
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.path_mgmt.base import PathMgmt
from lib.packet.path_mgmt.seg_req import PathSegmentReq
from lib.path_db import PathSegmentDB
from lib.types import PathSegmentType as PST
from path_server.base import PathServer, REQS_TOTAL


class LocalPathServer(PathServer):
    """
    SCION Path Server in a non-core AS. Stores up-segments to the core and
    registers down-segments with the CPS. Can cache segments learned from a CPS.
    """

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
        # Sanity check that we should indeed be a local path server.
        assert not self.topology.is_core_as, "This shouldn't be a core PS!"
        # Database of up-segments to the core.
        up_labels = {**self._labels, "type": "up"} if self._labels else None
        self.up_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO, labels=up_labels)

    def _handle_up_segment_record(self, pcb, from_zk=False):
        if not from_zk:
            self._segs_to_zk[pcb.get_hops_hash()] = (PST.UP, pcb)
        if self._add_segment(pcb, self.up_segments, "Up"):
            # Sending pending targets to the core using first registered
            # up-segment.
            self._handle_waiting_targets(pcb)
            return set([(pcb.first_ia(), pcb.is_sibra())])
        return set()

    def _handle_down_segment_record(self, pcb, from_zk=None):
        if self._add_segment(pcb, self.down_segments, "Down"):
            return set([(pcb.last_ia(), pcb.is_sibra())])
        return set()

    def _handle_core_segment_record(self, pcb, from_zk=None):
        if self._add_segment(pcb, self.core_segments, "Core"):
            return set([(pcb.first_ia(), pcb.is_sibra())])
        return set()

    def path_resolution(self, cpld, meta, new_request=True, logger=None):
        """
        Handle generic type of a path request.
        """
        pmgt = cpld.union
        req = pmgt.union
        assert isinstance(req, PathSegmentReq), type(req)
        if logger is None:
            logger = self.get_request_logger(cpld.req_id_str(), meta)
        dst_ia = req.dst_ia()
        if new_request:
            logger.info("PATH_REQ received: %s", req)
            REQS_TOTAL.labels(**self._labels).inc()
        if dst_ia == self.addr.isd_as:
            logger.warning("Dropping request: requested DST is local AS")
            return False
        up_segs = set()
        core_segs = set()
        down_segs = set()
        # dst as==0 means any core AS in the specified ISD
        if self.is_core_as(dst_ia) or dst_ia[1] == 0:
            self._resolve_core(req, up_segs, core_segs)
        else:
            self._resolve_not_core(req, up_segs, core_segs, down_segs, logger)
        if up_segs | core_segs | down_segs:
            self._send_path_segments(req, cpld.req_id, meta, logger, up_segs, core_segs, down_segs)
            return True
        if new_request:
            with self.pen_req_lock:
                self.pending_req[(dst_ia, req.p.flags.sibra)][str(meta)] = (
                    req, cpld.req_id, meta, logger)
            self._request_paths_from_core(req, logger)
        return False

    def _get_segs_from_buckets(self, buckets, total_segs):
        """
        Returns up to MAX_SEG_NO segments from all available segments in the buckets in
        Round-Robin fashion.
        """
        segs = []
        ias = set()
        if not total_segs:
            return segs, ias
        while buckets:
            for key in list(buckets.keys()):
                if len(segs) == self.MAX_SEG_NO or total_segs == 0:
                    return segs, ias
                if len(buckets[key]) > 0:
                    segs.append(buckets[key].pop(0))
                    total_segs -= 1
                    ias.add(key)
                else:
                    del buckets[key]
        return segs, ias

    def _core_segs(self, first_ias, last_ias, sibra):
        buckets = {}
        num_segs = 0
        for first_ia in first_ias:
            for last_ia in last_ias:
                params = first_ia.params()
                params["sibra"] = sibra
                params["last_ia"] = last_ia
                csegs = self.core_segments(**params)
                if csegs:
                    buckets[(first_ia, last_ia)] = csegs
                    num_segs += len(csegs)
        return buckets, num_segs

    def _up_segs(self, sibra):
        # Get list of reachable core ASes (core ASes that we have up segments for).
        buckets = defaultdict(list)
        num_segs = 0
        for useg in self.up_segments(sibra=sibra, full=True):
            buckets[useg.first_ia()].append(useg)
            num_segs += 1
        return buckets, num_segs

    def _down_segs(self, ia, sibra):
        # Get list of reachable core ASes (core ASes that we have down segments for).
        buckets = defaultdict(list)
        num_segs = 0
        for dseg in self.down_segments(last_ia=ia, sibra=sibra, full=True):
            buckets[dseg.first_ia()].append(dseg)
            num_segs += 1
        return buckets, num_segs

    def _filter_buckets(self, buckets, ias):
        filtered_buckets = {}
        num_segs = 0
        for ia in set(ias):
            bucket = buckets[ia]
            filtered_buckets[ia] = bucket
            num_segs += len(bucket)
        return filtered_buckets, num_segs

    def _resolve_core(self, req, up_segs, core_segs):
        """
        Dst is core AS.
        """
        dst_ia = req.dst_ia()
        params = dst_ia.params()
        sibra = req.p.flags.sibra
        params["sibra"] = sibra
        if dst_ia[0] == self.addr.isd_as[0]:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            up_segs.update(self.up_segments(**params))
        # Get list of reachable core ASes (core ASes that we have up segments for).
        buckets_up, _ = self._up_segs(sibra)
        # Get core segments between the destination and each reachable core AS.
        buckets_core, num_core_segs = self._core_segs([dst_ia], buckets_up.keys(), sibra)
        # Get usable core segments
        segs, ia_pairs = self._get_segs_from_buckets(buckets_core, num_core_segs)
        if not segs:
            return
        core_segs.update(segs)
        first_ias, last_ias = zip(*ia_pairs)
        # In this use case, first_ias is always the destination core AS
        buckets_up, num_up_segs = self._filter_buckets(buckets_up, last_ias)
        segs, _ = self._get_segs_from_buckets(buckets_up, num_up_segs)
        up_segs.update(segs)

    def _resolve_not_core(self, req, up_segs, core_segs, down_segs, logger):
        """
        Dst is regular AS.
        """
        dst_ia = req.dst_ia()
        sibra = req.p.flags.sibra
        buckets_up, up_seg_c = self._up_segs(sibra)
        buckets_down, down_seg_c = self._down_segs(dst_ia, sibra)
        up_core_ias = set(buckets_up.keys())
        down_core_ias = set(buckets_down.keys())
        buckets_core, num_core_segs = self._core_segs(down_core_ias, up_core_ias, sibra)
        common_core_ias = up_core_ias & down_core_ias
        for ia in common_core_ias:
            # Dst in local ISD. First add paths that do not require a core segment.
            # Get up segments to common core AS
            up_segs.update(buckets_up.pop(ia))
            # Get down segments to common core AS
            down_segs.update(buckets_down.pop(ia))
        # Get usable core segments
        segs, ia_pairs = self._get_segs_from_buckets(buckets_core, num_core_segs)
        if not segs:
            usegs, _ = self._get_segs_from_buckets(buckets_up, up_seg_c)
            dsegs, _ = self._get_segs_from_buckets(buckets_down, down_seg_c)
            # Compatibility with GO PS, we have to fetch missing core segs.
            for dseg in dsegs:
                for useg in usegs:
                    # Request missing_ias
                    src, dst = useg.first_ia(), dseg.first_ia()
                    if src != dst:
                        creq = PathSegmentReq.from_values(src_ia=src, dst_ia=dst)
                        self._request_paths_from_core(creq, logger)
            return
        core_segs.update(segs)
        first_ias, last_ias = zip(*ia_pairs)
        # Up segments
        buckets_up, num_segs = self._filter_buckets(buckets_up, last_ias)
        segs, _ = self._get_segs_from_buckets(buckets_up, num_segs)
        up_segs.update(segs)
        # Down segments
        buckets_down, num_segs = self._filter_buckets(buckets_down, first_ias)
        segs, _ = self._get_segs_from_buckets(buckets_down, num_segs)
        down_segs.update(segs)

    def _request_paths_from_core(self, req, logger):
        """
        Try to request core PS for given target.
        """
        up_segs = self.up_segments(sibra=req.p.flags.sibra)
        if not up_segs:
            logger.info('Pending target added.')
            # Wait for path to any local core AS
            self.waiting_targets[self.addr.isd_as[0]].append((req, logger))
            return

        # PSz: for multipath it makes sense to query with multiple core ASes
        pcb = up_segs[0]
        logger.info('Send request to core via %s', pcb.short_desc())
        path = pcb.get_path(reverse_direction=True)
        meta = self._build_meta(ia=pcb.first_ia(), path=path,
                                host=SVCType.PS_A, reuse=True)
        self.send_meta(CtrlPayload(PathMgmt(req.copy())), meta)

    def _forward_revocation(self, srev_info, meta):
        # Inform core ASes if the revoked interface belongs to this AS or
        # the revocation originates from a different ISD.
        rev_info = srev_info.rev_info()
        rev_isd_as = rev_info.isd_as()
        if (rev_isd_as == self.addr.isd_as or
                rev_isd_as[0] != self.addr.isd_as[0]):
            self._send_rev_to_core(srev_info)

    def _send_rev_to_core(self, srev_info):
        """
        Forwards a revocation to a core path service.

        :param signed_rev_info: SignedRevInfo
        """
        # Issue revocation to all core ASes excluding self.
        rev_info = srev_info.rev_info()
        paths = self.up_segments()
        if not paths:
            logging.warning("No paths to core ASes available for forwarding "
                            "revocation: %s", rev_info.short_desc())
            return
        seg = paths[0]
        core_ia = seg.first_ia()
        path = seg.get_path(reverse_direction=True)
        logging.info("Forwarding Revocation to %s using path:\n%s" %
                     (core_ia, seg.short_desc()))
        meta = self._build_meta(ia=core_ia, path=path, host=SVCType.PS_A)
        self.send_meta(CtrlPayload(PathMgmt(srev_info.copy())), meta)
