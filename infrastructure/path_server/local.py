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
from lib.packet.scion_addr import ISD_AD
from lib.path_db import DBResult, PathSegmentDB
from lib.types import PathSegmentType as PST


class LocalPathServer(PathServer):
    """
    SCION Path Server in a non-core AD. Stores up-paths to the core and
    registers down-paths with the CPS. Can cache paths learned from a CPS.
    """
    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        # Sanity check that we should indeed be a local path server.
        assert not self.topology.is_core_ad, "This shouldn't be a local PS!"
        # Database of up-segments to the core.
        self.up_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO)
        self._cached_seg_handler = self._handle_up_segment_record

    def _update_master(self):
        pass

    def _handle_up_segment_record(self, pkt, from_zk=False):
        """
        Handle Up Path registration from local BS or ZK's cache. Return a set of
        added destinations.
        """
        added = set()
        records = pkt.get_payload()
        if not records.pcbs[PST.UP]:
            return added
        for pcb in records.pcbs[PST.UP]:
            first_isd, first_ad = pcb.get_first_isd_ad()
            res = self.up_segments.update(pcb, first_isd, first_ad,
                                          self.addr.isd_id, self.addr.ad_id)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
                added.add((first_isd, first_ad))
                logging.info("Up-Segment registered (from zk: %s): %s",
                             from_zk, pcb.short_desc())
        # Share Up Segment via ZK.
        if not from_zk:
            self._share_segments(pkt)
        # Sending pending targets to the core using first registered up-path.
        self._handle_waiting_targets(records.pcbs[PST.UP][0])
        return added

    def _handle_down_segment_record(self, pkt):
        """
        Handle down segment record. Return a set of added destinations.
        """
        added = set()
        records = pkt.get_payload()
        if not records.pcbs[PST.DOWN]:
            return added
        for pcb in records.pcbs[PST.DOWN]:
            src_isd, src_ad = pcb.get_first_isd_ad()
            dst_isd, dst_ad = pcb.get_last_isd_ad()
            res = self.down_segments.update(pcb, src_isd, src_ad,
                                            dst_isd, dst_ad)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
                added.add((dst_isd, dst_ad))
                logging.info("Down-Seg registered: %s", pcb.short_desc())
        return added

    def _handle_core_segment_record(self, pkt):
        """
        Handle registration of a core path. Return a set of added destinations.
        """
        added = set()
        records = pkt.get_payload()
        if not records.pcbs[PST.CORE]:
            return added
        for pcb in records.pcbs[PST.CORE]:
            # Core segments have down-path direction.
            src_isd, src_ad = pcb.get_last_isd_ad()
            dst_isd, dst_ad = pcb.get_first_isd_ad()
            res = self.core_segments.update(pcb, first_isd=dst_isd,
                                            first_ad=dst_ad, last_isd=src_isd,
                                            last_ad=src_ad)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
                added.add((dst_isd, dst_ad))
                logging.info("Core-Segment registered: %s", pcb.short_desc())
        return added

    def _handle_sibra_segment_record(self, pkt, from_zk=False):
        records = pkt.get_payload()
        for seg in records.sibra_segs:
            self._add_sibra_segment(seg)
        if not from_zk:
            self._share_segments(pkt)
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
        seg_info = pkt.get_payload()
        seg_type = seg_info.seg_type
        dst = ISD_AD(seg_info.dst_isd, seg_info.dst_ad)
        assert seg_type == PST.GENERIC
        logging.info("PATH_REQ received, addr: %d,%d" % dst)
        if dst == self.addr.get_isd_ad():
            logging.warning("Dropping request: requested DST is local AD")
            return False

        # dst_ad=0 means any core AS in the specified ISD
        dst_is_core = dst in self._core_ads[dst.isd] or not seg_info.dst_ad
        dst_in_local_isd = (dst.isd == self.addr.isd_id)
        down_seg = set()
        if dst_is_core:
            up_seg, core_seg = self._resolve_core(dst.isd, dst.ad,
                                                  dst_in_local_isd)
        else:
            up_seg, core_seg, down_seg = self._resolve_not_core(
                dst.isd, dst.ad, dst_in_local_isd)

        if not (up_seg | core_seg | down_seg):
            if new_request:
                logging.debug("Segs to %d,%d not found, querying core." % dst)
                self._request_paths_from_core(dst.isd, dst.ad)
                self.pending_req[dst].append(pkt)
            else:
                # That could happend when needed segment expired.
                logging.warning("Handling pending request and needed seg"
                                "is missing. Shouldn't be here (too often).")
            return False

        logging.debug("Sending segments to %d,%d" % dst)
        self._send_path_segments(pkt, up_seg, core_seg, down_seg)
        return True

    def _resolve_core(self, dst_isd, dst_ad, dst_in_local_isd):
        """
        Dst is core AS.
        """
        up_seg = set()
        core_seg = set()
        params = {"first_isd": dst_isd}
        if dst_ad:
            params["first_ad"] = dst_ad
        if dst_in_local_isd:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            up_seg.update(self.up_segments(**params))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(**params):
            # Check do we have an up-seg that is connected to core_seg.
            isd, ad = cseg.get_last_isd_ad()
            tmp_up_segs = self.up_segments(first_isd=isd, first_ad=ad)
            if tmp_up_segs:
                up_seg.update(tmp_up_segs)
                core_seg.add(cseg)
        return up_seg, core_seg

    def _resolve_not_core(self, dst_isd, dst_ad, dst_in_local_isd):
        """
        Dst is regular AS.
        """
        up_seg = set()
        core_seg = set()
        down_seg = set()
        # Check if there exists down-seg to DST.
        for dseg in self.down_segments(last_isd=dst_isd, last_ad=dst_ad):
            isd, ad = dseg.get_first_isd_ad()
            if dst_in_local_isd:
                # Dst in local ISD. First try to find direct up-seg.
                tmp_up_seg = self.up_segments(first_isd=isd, first_ad=ad)
                if tmp_up_seg:
                    up_seg.update(tmp_up_seg)
                    down_seg.add(dseg)
            # Now try core segments that connect to down segment.
            # PSz: it might make sense to start with up_segments instead.
            for cseg in self.core_segments(first_isd=isd, first_ad=ad):
                isd_, ad_ = cseg.get_last_isd_ad()
                # And up segments that connect to core segment.
                tmp_up_seg = self.up_segments(first_isd=isd_, first_ad=ad_)
                if tmp_up_seg:
                    up_seg.update(tmp_up_seg)
                    down_seg.add(dseg)
                    core_seg.add(cseg)
        return up_seg, core_seg, down_seg

    def _request_paths_from_core(self, dst_isd, dst_ad):
        """
        Try to request core PS for given target (isd, ad).
        """
        src_isd, src_ad = self.addr.get_isd_ad()
        seg_info = PathSegmentInfo.from_values(PST.GENERIC, src_isd, src_ad,
                                               dst_isd, dst_ad)
        if not len(self.up_segments()):
            logging.info('Pending target added (%d, %d)', dst_isd, dst_ad)
            self.waiting_targets.add((dst_isd, dst_ad, seg_info))
            return

        # PSz: for multipath it makes sense to query with multiple core ASes
        pcb = self.up_segments()[0]
        logging.info('Requesting core for %d,%d via %s',
                     dst_isd, dst_ad, pcb.short_desc())
        path = pcb.get_path(reverse_direction=True)
        req_pkt = self._build_packet(PT.PATH_MGMT, payload=seg_info, path=path,
                                     dst_isd=pcb.get_isd(),
                                     dst_ad=pcb.get_first_pcbm().ad_id)
        self._send_to_next_hop(req_pkt, path.get_fwd_if())
