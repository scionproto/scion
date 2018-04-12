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
:mod:`local` --- Local path server
==================================
"""
# Stdlib
import logging

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

    def __init__(self, server_id, conf_dir, spki_cache_dir=GEN_CACHE_PATH, prom_export=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        super().__init__(server_id, conf_dir, spki_cache_dir=spki_cache_dir,
                         prom_export=prom_export)
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
            self._resolve_not_core(req, up_segs, core_segs, down_segs)
        if up_segs | core_segs | down_segs:
            self._send_path_segments(req, cpld.req_id, meta, logger, up_segs, core_segs, down_segs)
            return True
        if new_request:
            self._request_paths_from_core(req, logger)
            self.pending_req[(dst_ia, req.p.flags.sibra)][str(meta)] = (
                req, cpld.req_id, meta, logger)
        return False

    def _resolve_core(self, req, up_segs, core_segs):
        """
        Dst is core AS.
        """
        dst_ia = req.dst_ia()
        params = dst_ia.params()
        params["sibra"] = req.p.flags.sibra
        if dst_ia[0] == self.addr.isd_as[0]:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            up_segs.update(self.up_segments(**params))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(**params):
            # Check do we have an up-seg that is connected to core_seg.
            tmp_up_segs = self.up_segments(first_ia=cseg.last_ia(),
                                           sibra=req.p.flags.sibra)
            if tmp_up_segs:
                up_segs.update(tmp_up_segs)
                core_segs.add(cseg)

    def _resolve_not_core(self, req, up_segs, core_segs, down_segs):
        """
        Dst is regular AS.
        """
        sibra = req.p.flags.sibra
        # Check if there exists down-seg to DST.
        for dseg in self.down_segments(last_ia=req.dst_ia(), sibra=sibra):
            first_ia = dseg.first_ia()
            if req.dst_ia()[0] == self.addr.isd_as[0]:
                # Dst in local ISD. First try to find direct up-seg.
                dir_up_segs = self.up_segments(first_ia=first_ia, sibra=sibra)
                if dir_up_segs:
                    up_segs.update(dir_up_segs)
                    down_segs.add(dseg)
            # Now try core segments that connect to down segment.
            # PSz: it might make sense to start with up_segments instead.
            for cseg in self.core_segments(first_ia=first_ia, sibra=sibra):
                # And up segments that connect to core segment.
                up_core_segs = self.up_segments(first_ia=cseg.last_ia(),
                                                sibra=sibra)
                if up_core_segs:
                    up_segs.update(up_core_segs)
                    core_segs.add(cseg)
                    down_segs.add(dseg)

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

    def _forward_revocation(self, rev_info, meta):
        # Inform core ASes if the revoked interface belongs to this AS or
        # the revocation originates from a different ISD.
        rev_isd_as = rev_info.isd_as()
        if (rev_isd_as == self.addr.isd_as or
                rev_isd_as[0] != self.addr.isd_as[0]):
            self._send_rev_to_core(rev_info)

    def _send_rev_to_core(self, rev_info):
        """
        Forwards a revocation to a core path service.

        :param rev_info: The RevocationInfo object
        """
        # Issue revocation to all core ASes excluding self.
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
        self.send_meta(CtrlPayload(PathMgmt(rev_info.copy())), meta)
