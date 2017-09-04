# Copyright 2017 ETH Zurich
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
:mod:`local` --- Hidden path server
===================================
"""
# Stdlib
import logging
import os
import random

# SCION
from lib.crypto.hash_tree import ConnectedHashTree
from lib.defines import HIDDEN_PATH_CONF_FILE, HIDDEN_PATH_SERVICE
from lib.hps_config import HPSClient
from lib.packet.svc import SVCType
from lib.path_db import DBResult, PathSegmentDB
from lib.types import PathSegmentType as PST
from path_server.base import PathServer, REQS_TOTAL


class HiddenPathServer(PathServer):
    """
    SCION Hidden Path Server that stores hidden down-segments to the hidden AS.
    """
    SERVICE_TYPE = HIDDEN_PATH_SERVICE

    def __init__(self, server_id, conf_dir, prom_export=None):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param str prom_export: prometheus export address.
        """
        super().__init__(server_id, conf_dir, prom_export)
        # Sanity check that we should indeed be a local path server.
        # Database of up-segments to the core.
        up_labels = {**self._labels, "type": "up"} if self._labels else None
        self.up_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO, labels=up_labels)
        self.hpservice = HPSClient.from_values(
            self.addr.isd_as,
            os.path.join(os.path.dirname(conf_dir), HIDDEN_PATH_CONF_FILE))
        self.hidden_segments = {}

    def _handle_up_segment_record(self, pcb, from_zk=False):
        if not from_zk:
            self._segs_to_zk[pcb.get_hops_hash()] = (PST.UP, pcb)
        if self._add_segment(pcb, self.up_segments, "Up"):
            # Sending pending targets to the core using first registered
            # up-segment.
            self._handle_waiting_targets(pcb)
            return set([(pcb.first_ia(), pcb.is_sibra())])
        return set()

    def _handle_down_segment_record(self, pcb, from_zk=None, setInfos=None):
        """
        Register a hidden down-segments depending on the set information.
        """
        added = False
        if setInfos:
            for setInfo in setInfos:
                if setInfo not in self.hidden_segments:
                    down_labels = {**self._labels, "type": "down"} if self._labels else None
                    hidden_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO,
                                                    labels=down_labels)
                    self.hidden_segments[setInfo] = hidden_segments
                if self._add_segment(pcb, self.hidden_segments[setInfo], "Down"):
                    added = True
        if added:
            return set([(pcb.last_ia(), pcb.is_sibra())])
        return set()

    def _handle_core_segment_record(self, pcb, from_zk=None):
        if self._add_segment(pcb, self.core_segments, "Core"):
            return set([(pcb.first_ia(), pcb.is_sibra())])
        return set()

    def path_resolution(self, req, meta, new_request=True, logger=None, req_id=None):
        """
        Handle a hidden path request.
        """
        # Random ID for a request.
        req_id = req_id or random.randint(0, 2**32 - 1)
        if logger is None:
            logger = self.get_request_logger(req, req_id, meta)
        dst_ia = req.dst_ia()
        if new_request:
            logger.info("PATH_REQ received")
            REQS_TOTAL.labels(**self._labels).inc()
        if dst_ia == self.addr.isd_as:
            logger.warning("Dropping request: requested DST is local AS")
            return False
        down_segs = set()
        self._resolve_hidden(req, down_segs)
        if down_segs:
            self._send_path_segments(req, meta, logger, down=down_segs)
            return True
        if new_request:
            self.pending_req[(dst_ia, req.p.flags.sibra)][req_id] = (req, meta, logger)

        return False

    def _resolve_hidden(self, req, down_segs):
        """
        Look up hidden segments for a requester and resolve them as down segments
        :param PathRecordReq req: the path request info
        :param set down_segs: The container of resolved down segments
        """
        src_ia = req.src_ia()
        dst_ia = req.dst_ia()
        set_id = req.set_id()
        sibra = req.p.flags.sibra
        for setInfo, hidden_segments in self.hidden_segments.items():
            if set_id == setInfo.set_id() and src_ia in setInfo.iter_member_ias():
                for dseg in hidden_segments(last_ia=dst_ia, sibra=sibra):
                    down_segs.add(dseg)

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
            hidden_segs_removed = 0
            for h in (hash01, hash12):
                for sid in self.htroot_if2seg.pop((h, if_id), []):
                    deleted = False
                    for _, hidden_segments in self.hidden_segments.items():
                        if hidden_segments.delete(sid) == DBResult.ENTRY_DELETED:
                            deleted = True
                    if deleted:
                        hidden_segs_removed += 1
            for set_id, hidden_segments in self.hidden_segments.items():
                if len(hidden_segments) is 0:
                    del self.hidden_segments[set_id]

            logging.debug("Removed segments revoked by [%s]: HIDDEN: %d" %
                          (rev_info.short_desc(), hidden_segs_removed))

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
            logging.warning("No paths to core ASes available for forwarding"
                            "revocation: %s", rev_info.short_desc())
            return
        seg = paths[0]
        core_ia = seg.first_ia()
        path = seg.get_path(reverse_direction=True)
        logging.info("Forwarding Revocation to %s using path:\n%s" %
                     (core_ia, seg.short_desc()))
        meta = self._build_meta(ia=core_ia, path=path, host=SVCType.PS_A)
        self.send_meta(rev_info.copy(), meta)
