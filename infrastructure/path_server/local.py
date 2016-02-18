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
from lib.packet.path_mgmt import PathSegmentInfo
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
            return set([pcb.get_first_pcbm().isd_as])
        return set()

    def _handle_sibra_segment_record(self, pcb, from_zk=False):
        if not from_zk:
            self._segs_to_zk.append((PST.SIBRA, pcb))
        if self._add_segment(pcb, self.sibra_segments, "SIBRA"):
            return set([pcb.get_first_pcbm().isd_as])
        return set()

    def _handle_down_segment_record(self, pcb):
        if self._add_segment(pcb, self.down_segments, "Down"):
            return set([pcb.get_last_pcbm().isd_as])
        return set()

    def _handle_core_segment_record(self, pcb):
        if self._add_segment(pcb, self.core_segments, "Core"):
            return set([pcb.get_first_pcbm().isd_as])
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
                self.sibra_segments.delete(sid)
            if rev_token in self.iftoken2seg:
                del self.iftoken2seg[rev_token]
            rev_token = SHA256.new(rev_token).digest()

    def path_resolution(self, pkt, new_request=True):
        """
        Handle generic type of a path request.
        """
        seg_info = pkt.get_payload()
        seg_type = seg_info.seg_type
        assert seg_type == PST.GENERIC
        dst_ia = seg_info.dst_ia
        logging.info("PATH_REQ received, addr: %s" % dst_ia)
        if dst_ia == self.addr.isd_as:
            logging.warning("Dropping request: requested DST is local AS")
            return False

        # dst as==0 means any core AS in the specified ISD
        dst_is_core = self._is_core_as(dst_ia) or dst_ia[1] == 0
        dst_in_local_isd = dst_ia[0] == self.addr.isd_as[0]
        down_seg = set()
        if dst_is_core:
            up_seg, core_seg = self._resolve_core(dst_ia, dst_in_local_isd)
        else:
            up_seg, core_seg, down_seg = self._resolve_not_core(
                dst_ia, dst_in_local_isd)
        if not (up_seg | core_seg | down_seg):
            if new_request:
                logging.debug("Segs to %s not found, querying core." % dst_ia)
                self._request_paths_from_core(dst_ia)
                self.pending_req[dst_ia].append(pkt)
            else:
                # That could happend when needed segment expired.
                logging.warning("Handling pending request and needed seg "
                                "is missing. Shouldn't be here (too often).")
            return False

        logging.debug("Sending segments to %s" % dst_ia)
        self._send_path_segments(pkt, up_seg, core_seg, down_seg)
        return True

    def _resolve_core(self, dst_ia, dst_in_local_isd):
        """
        Dst is core AS.
        """
        up_seg = set()
        core_seg = set()
        params = dst_ia.params()
        if dst_in_local_isd:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            up_seg.update(self.up_segments(**params))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(**params):
            # Check do we have an up-seg that is connected to core_seg.
            cseg_ia = cseg.get_last_pcbm().isd_as
            tmp_up_segs = self.up_segments(first_ia=cseg_ia)
            if tmp_up_segs:
                up_seg.update(tmp_up_segs)
                core_seg.add(cseg)
        return up_seg, core_seg

    def _resolve_not_core(self, dst_ia, dst_in_local_isd):
        """
        Dst is regular AS.
        """
        up_seg = set()
        core_seg = set()
        down_seg = set()
        # Check if there exists down-seg to DST.
        for dseg in self.down_segments(last_ia=dst_ia):
            first_ia = dseg.get_first_pcbm().isd_as
            if dst_in_local_isd:
                # Dst in local ISD. First try to find direct up-seg.
                tmp_up_seg = self.up_segments(first_ia=first_ia)
                if tmp_up_seg:
                    up_seg.update(tmp_up_seg)
                    down_seg.add(dseg)
            # Now try core segments that connect to down segment.
            # PSz: it might make sense to start with up_segments instead.
            for cseg in self.core_segments(first_ia=first_ia):
                last_ia = cseg.get_last_pcbm().isd_as
                # And up segments that connect to core segment.
                tmp_up_seg = self.up_segments(first_ia=last_ia)
                if tmp_up_seg:
                    up_seg.update(tmp_up_seg)
                    down_seg.add(dseg)
                    core_seg.add(cseg)
        return up_seg, core_seg, down_seg

    def _request_paths_from_core(self, dst_ia):
        """
        Try to request core PS for given target.
        """
        seg_info = PathSegmentInfo.from_values(PST.GENERIC, self.addr.isd_as,
                                               dst_ia)
        if not len(self.up_segments()):
            logging.info('Pending target added: %s', dst_ia)
            self.waiting_targets.add((dst_ia, seg_info))
            return

        # PSz: for multipath it makes sense to query with multiple core ASes
        pcb = self.up_segments()[0]
        logging.info('Requesting core for %s via %s', dst_ia, pcb.short_desc())
        path = pcb.get_path(reverse_direction=True)
        req_pkt = self._build_packet(PT.PATH_MGMT, payload=seg_info, path=path,
                                     dst_ia=pcb.get_first_pcbm().isd_as)
        self._send_to_next_hop(req_pkt, path.get_fwd_if())
