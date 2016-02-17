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

# External packages
from Crypto.Hash import SHA256

# SCION
from infrastructure.path_server.base import PathServer
from lib.flagtypes import PathSegFlags as PSF
from lib.packet.scion import PacketType as PT
from lib.path_db import PathSegmentDB
from lib.types import PathSegmentType as PST


class LocalPathServer(PathServer):
    """
    SCION Path Server in a non-core AS. Stores up-segments to the core and
    registers down-segments with the CPS. Can cache segments learned from a CPS.
    """
    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        # Sanity check that we should indeed be a local path server.
        assert not self.topology.is_core_as, "This shouldn't be a core PS!"
        # Database of up-segments to the core.
        self.up_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO)

    def _handle_up_segment_record(self, pcb, from_zk=False):
        if not from_zk:
            self._segs_to_zk.append((PST.UP, pcb))
        if self._add_segment(pcb, self.up_segments, "Up"):
            # Sending pending targets to the core using first registered
            # up-segment.
            self._handle_waiting_targets(pcb)
            return set([(pcb.get_first_pcbm().isd_as, pcb.is_sibra())])
        return set()

    def _handle_down_segment_record(self, pcb):
        if self._add_segment(pcb, self.down_segments, "Down"):
            return set([(pcb.get_last_pcbm().isd_as, pcb.is_sibra())])
        return set()

    def _handle_core_segment_record(self, pcb):
        if self._add_segment(pcb, self.core_segments, "Core"):
            return set([(pcb.get_first_pcbm().isd_as, pcb.is_sibra())])
        return set()

    def _remove_revoked_segments(self, rev_info):
        """
        Remove segments that contain a revoked interface. Checks 20 tokens in
        case previous revocations were missed by the PS.

        :param rev_info: The revocation info
        :type rev_info: RevocationInfo
        """
        rev_token = rev_info.rev_token
        for _ in range(self.N_TOKENS_CHECK):
            segments = self.iftoken2seg[rev_token]
            while segments:
                sid = segments.pop()
                # Delete segment from DB.
                self.up_segments.delete(sid)
                self.down_segments.delete(sid)
                self.core_segments.delete(sid)
            if rev_token in self.iftoken2seg:
                del self.iftoken2seg[rev_token]
            rev_token = SHA256.new(rev_token).digest()

    def path_resolution(self, pkt, new_request=True):
        """
        Handle generic type of a path request.
        """
        seg_req = pkt.get_payload()
        dst_ia = seg_req.dst_ia
        if new_request:
            logging.info("PATH_REQ received: %s", seg_req.short_desc())
        if dst_ia == self.addr.isd_as:
            logging.warning("Dropping request: requested DST is local AS")
            return False
        up_segs = set()
        core_segs = set()
        down_segs = set()
        # dst as==0 means any core AS in the specified ISD
        if self._is_core_as(dst_ia) or dst_ia[1] == 0:
            self._resolve_core(seg_req, up_segs, core_segs)
        else:
            self._resolve_not_core(seg_req, up_segs, core_segs, down_segs)
        all_segs = up_segs | core_segs | down_segs
        if all_segs:
            logging.debug("Replying with %s segments to %s",
                          len(all_segs), seg_req.short_desc())
            self._send_path_segments(pkt, up_segs, core_segs, down_segs)
            return True
        if new_request:
            self._request_paths_from_core(seg_req)
            sibra = bool(seg_req.flags & PSF.SIBRA)
            self.pending_req[(dst_ia, sibra)].append(pkt)
        else:
            # That could happend when needed segment expired.
            logging.warning("Handling pending request and needed seg "
                            "is missing. Shouldn't be here (too often).")
        return False

    def _resolve_core(self, seg_req, up_segs, core_segs):
        """
        Dst is core AS.
        """
        sibra = bool(seg_req.flags & PSF.SIBRA)
        params = seg_req.dst_ia.params()
        params["sibra"] = sibra
        if seg_req.dst_ia[0] == self.addr.isd_as[0]:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            up_segs.update(self.up_segments(**params))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(**params):
            # Check do we have an up-seg that is connected to core_seg.
            cseg_ia = cseg.get_last_pcbm().isd_as
            tmp_up_segs = self.up_segments(first_ia=cseg_ia, sibra=sibra)
            if tmp_up_segs:
                up_segs.update(tmp_up_segs)
                core_segs.add(cseg)

    def _resolve_not_core(self, seg_req, up_segs, core_segs, down_segs):
        """
        Dst is regular AS.
        """
        sibra = bool(seg_req.flags & PSF.SIBRA)
        # Check if there exists down-seg to DST.
        for dseg in self.down_segments(last_ia=seg_req.dst_ia, sibra=sibra):
            first_ia = dseg.get_first_pcbm().isd_as
            if seg_req.dst_ia[0] == self.addr.isd_as[0]:
                # Dst in local ISD. First try to find direct up-seg.
                dir_up_segs = self.up_segments(first_ia=first_ia, sibra=sibra)
                if dir_up_segs:
                    up_segs.update(dir_up_segs)
                    down_segs.add(dseg)
            # Now try core segments that connect to down segment.
            # PSz: it might make sense to start with up_segments instead.
            for cseg in self.core_segments(first_ia=first_ia, sibra=sibra):
                last_ia = cseg.get_last_pcbm().isd_as
                # And up segments that connect to core segment.
                up_core_segs = self.up_segments(first_ia=last_ia, sibra=sibra)
                if up_core_segs:
                    up_segs.update(up_core_segs)
                    core_segs.add(cseg)
                    down_segs.add(dseg)

    def _request_paths_from_core(self, seg_req):
        """
        Try to request core PS for given target.
        """
        sibra = bool(seg_req.flags & PSF.SIBRA)
        up_segs = self.up_segments(sibra=sibra)
        if not up_segs:
            logging.info('Pending target added for %s',
                         seg_req.short_desc())
            # Wait for path to any local core AS
            self.waiting_targets[self.addr.isd_as[0]].append(seg_req)
            return

        # PSz: for multipath it makes sense to query with multiple core ASes
        pcb = up_segs[0]
        logging.info('Send request to core (%s) via %s',
                     seg_req.short_desc(), pcb.short_desc())
        path = pcb.get_path(reverse_direction=True)
        req_pkt = self._build_packet(PT.PATH_MGMT, payload=seg_req, path=path,
                                     dst_ia=pcb.get_first_pcbm().isd_as)
        self._send_to_next_hop(req_pkt, path.get_fwd_if())
