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
:mod:`core` --- Core path server
================================
"""
# Stdlib
import logging
from collections import deque

# SCION
from infrastructure.path_server.base import PathServer
from lib.packet.host_addr import haddr_parse
from lib.packet.path_mgmt import (
    PathRecordsReply,
    PathSegmentInfo,
)
from lib.packet.scion import PacketType as PT
from lib.types import PathMgmtType as PMT, PathSegmentType as PST
from lib.zookeeper import ZkNoConnection


class CorePathServer(PathServer):
    """
    SCION Path Server in a core AS. Stores intra ISD down-segments as well as
    core segments and forwards inter-ISD path requests to the corresponding path
    server.
    """
    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        # Sanity check that we should indeed be a core path server.
        assert self.topology.is_core_as, "This shouldn't be a local PS!"
        self._master_id = None  # Address of master core Path Server.
        self._segs_to_master = deque()
        self._segs_to_prop = deque()

    def _update_master(self):
        """
        Read master's address from shared lock, and if new master is elected
        sync it with segments.
        """
        try:
            curr_master = self.zk.get_lock_holder()
        except ZkNoConnection:
            logging.warning("_update_master(): ZkNoConnection.")
            return
        if not curr_master:
            logging.warning("_update_master(): current master is None.")
            return
        if curr_master != self._master_id:
            self._master_id = curr_master
            logging.debug("New master is: %s", self._master_id)
            self._sync_master()

    def _sync_master(self):
        """
        Feed newly-elected master with segments.
        """
        # TODO(PSz): consider mechanism for avoiding a registration storm.
        master = self._master_id
        if not master or self._is_master():
            logging.warning('Sync abandoned: master not set or I am a master')
            return
        core_segs = []
        # Find all core segments from remote ISDs
        for pcb in self.core_segments(full=True):
            if pcb.get_first_pcbm().isd_as[0] != self.addr.isd_as[0]:
                core_segs.append(pcb)
        # Find down-segments from local ISD.
        down_segs = self.down_segments(full=True, last_isd=self.addr.isd_as[0])
        logging.debug("Syncing with %s" % master)
        seen_ases = set()
        for seg_type, segs in [(PST.CORE, core_segs), (PST.DOWN, down_segs)]:
            for pcb in segs:
                key = pcb.get_first_pcbm().isd_as, pcb.get_last_pcbm().isd_as
                # Send only one segment for given (src, dst) pair.
                if key in seen_ases:
                    continue
                seen_ases.add(key)
                self._segs_to_prop.append((seg_type, pcb))
        for seg in self.sibra_segments(full=True):
            self._segs_to_prop.append((PST.SIBRA, seg))

    def _is_master(self):
        return self._master_id == str(self.addr.host)

    def _handle_up_segment_record(self, pcb, **kwargs):
        logging.error("Core Path Server received up-segment record!")
        return set()

    def _handle_down_segment_record(self, pcb, from_master=False):
        added = self._add_segment(pcb, self.down_segments, "Down")
        self._local_seg_prop(pcb, PST.DOWN, from_master)
        if added:
            return set([pcb.get_last_pcbm().isd_as])
        return set()

    def _handle_sibra_segment_record(self, pcb, from_master=False):
        added = self._add_segment(pcb, self.sibra_segments, "Down")
        self._local_seg_prop(pcb, PST.SIBRA, from_master)
        if added:
            return set([pcb.get_last_pcbm().isd_as])
        return set()

    def _local_seg_prop(self, pcb, type_, from_master):
        first_ia = pcb.get_first_pcbm().isd_as
        last_ia = pcb.get_last_pcbm().isd_as
        if first_ia == self.addr.isd_as:
            # Segment is to us, so propagate to all other core ASes within the
            # local ISD.
            self._segs_to_prop.append((type_, pcb))
        if (first_ia[0] == last_ia[0] == self.addr.isd_as[0] and not
                from_master):
            # Master gets a copy of all local segments.
            self._segs_to_master.append((type_, pcb))

    def _handle_core_segment_record(self, pcb, from_master=False,
                                    from_zk=False):
        """Handle registration of a core segment."""
        first_ia = pcb.get_first_pcbm().isd_as
        added = self._add_segment(pcb, self.core_segments, "Core")
        if not from_zk and not from_master:
            if first_ia[0] == self.addr.isd_as[0]:
                # Local core segment, share via ZK
                self._segs_to_zk.append((PST.CORE, pcb))
            elif self._master_id:
                # Remote core segment, send to master
                self._segs_to_master.append((PST.CORE, pcb))
        if not added:
            return set()
        # Send pending requests that couldn't be processed due to the lack of
        # a core segment to the destination PS.
        self._handle_waiting_targets(pcb)
        if first_ia[0] == self.addr.isd_as[0]:
            # Local core segment, just signal the specific AS
            return set([first_ia])
        else:
            # Remote core segment, signal the entire ISD
            return set([first_ia.any_as()])

    def _dispatch_params(self, pkt):
        pld = pkt.get_payload()
        params = {}
        if (pkt.addrs.src.isd_as == self.addr.isd_as and
                pld.PAYLOAD_TYPE == PMT.REPLY):
            params["from_master"] = True
        return params

    def _propagate_and_sync(self):
        super()._propagate_and_sync()
        self._prop_to_core()
        self._prop_to_master()

    def _prop_to_core(self):
        if not self._segs_to_prop:
            return
        logging.info("Propagating %d segment(s) to other core ASes",
                     len(self._segs_to_prop))
        for pcbs in self._gen_prop_recs(self._segs_to_prop):
            self._propagate_to_core_ases(PathRecordsReply.from_values(pcbs))

    def _prop_to_master(self):
        if self._is_master():
            self._segs_to_master.clear()
            return
        if not self._segs_to_master:
            return
        logging.info("Propagating %d segment(s) to master PS",
                     len(self._segs_to_master))
        for pcbs in self._gen_prop_recs(self._segs_to_master):
            self._send_to_master(PathRecordsReply.from_values(pcbs))

    def _send_to_master(self, pld):
        """
        Send the payload to the master PS.
        """
        master = self._master_id
        if self._is_master():
            return
        if not master:
            logging.warning("_send_to_master(): _master_id not set.")
            return
        pkt = self._build_packet(haddr_parse("IPV4", master), payload=pld)
        self.send(pkt, master)
        logging.debug("Packet sent to master %s", master)

    def _query_master(self, seg_type, dst_ia, src_ia=None):
        """
        Query master for a segment.
        """
        if self._is_master():
            logging.debug("I'm master, query abandoned.")
            return
        if src_ia is None:
            src_ia = self.addr.isd_as
        info = PathSegmentInfo.from_values(seg_type, src_ia, dst_ia)
        logging.debug("Asking master for segment: %s" % info)
        self._send_to_master(info)

    def _propagate_to_core_ases(self, rep_recs):
        """
        Propagate 'pkt' to other core ASes.
        """
        for isd_as in self._core_ases[self.addr.isd_as[0]]:
            if isd_as == self.addr.isd_as:
                continue
            csegs = self.core_segments(first_ia=isd_as,
                                       last_ia=self.addr.isd_as)
            if not csegs:
                logging.warning("Segment to AS %s not found.", isd_as)
                continue
            cseg = csegs[0].get_path(reverse_direction=True)
            pkt = self._build_packet(PT.PATH_MGMT, dst_ia=isd_as, path=cseg,
                                     payload=rep_recs)
            self._send_to_next_hop(pkt, cseg.get_fwd_if())

    def path_resolution(self, pkt, new_request=True):
        """
        Handle generic type of a path request.
        new_request informs whether a pkt is a new request (True), or is a
        pending request (False).
        Return True when resolution succeeded, False otherwise.
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
        if dst_is_core:
            core_seg = self._resolve_core(pkt, dst_ia, new_request)
            down_seg = set()
        else:
            core_seg, down_seg = self._resolve_not_core(
                pkt, dst_ia, new_request)

        if not (core_seg | down_seg):
            if new_request:
                logging.debug("Segs to %s not found." % dst_ia)
            else:
                # That could happen when a needed segment has expired.
                logging.warning("Handling pending request and needed segment "
                                "is missing. Shouldn't be here (too often).")
            return False

        self._send_path_segments(pkt, None, core_seg, down_seg)
        return True

    def _resolve_core(self, pkt, dst_ia, new_request):
        """
        Dst is core AS.
        """
        params = {"last_ia": self.addr.isd_as}
        params.update(dst_ia.params())
        core_seg = set(self.core_segments(**params))
        if not core_seg and new_request:
            # Segments not found and it is a new request.
            self.pending_req[dst_ia].append(pkt)
            # If dst is in remote ISD then a segment may be kept by master.
            if dst_ia[0] != self.addr.isd_as[0]:
                self._query_master(PST.GENERIC, dst_ia)
        return core_seg

    def _resolve_not_core(self, pkt, dst_ia, new_request):
        """
        Dst is regular AS.
        """
        core_seg = set()
        down_seg = set()
        # Check if there exists down-seg to dst.
        tmp_down_seg = self.down_segments(last_ia=dst_ia)
        if not tmp_down_seg and new_request:
            self._resolve_not_core_failed(pkt, dst_ia)

        for dseg in tmp_down_seg:
            dseg_ia = dseg.get_first_pcbm().isd_as
            # Check whether it is a direct down segment.
            if dseg_ia == self.addr.isd_as:
                down_seg.add(dseg)
                continue

            # Now try core segments that connect to down segment.
            tmp_core_seg = self.core_segments(first_ia=dseg_ia,
                                              last_ia=self.addr.isd_as)
            if not tmp_core_seg and new_request:
                # Core segment not found and it is a new request.
                self.pending_req[dseg_ia].append(pkt)
                if dst_ia[0] != self.addr.isd_as[0]:
                    # Master may know a segment.
                    self._query_master(PST.GENERIC, dseg_ia)
            elif tmp_core_seg:
                down_seg.add(dseg)
                core_seg.update(tmp_core_seg)
        return core_seg, down_seg

    def _resolve_not_core_failed(self, pkt, dst_ia):
        """
        Execute after _resolve_not_core() cannot resolve a new request, due to
        lack of corresponding down segment(s).
        This must not be executed for a pending request.
        """
        self.pending_req[dst_ia].append(pkt)
        if dst_ia[0] == self.addr.isd_as[0]:
            # Master may know down segment as dst is in local ISD.
            self._query_master(PST.GENERIC, dst_ia)
            return

        # Dst is in a remote ISD, ask any AS from there.
        csegs = self.core_segments(first_isd=dst_ia[0],
                                   last_ia=self.addr.isd_as)
        seg_info = pkt.get_payload()
        if csegs:
            path = csegs[0].get_path(reverse_direction=True)
            dst_ia = csegs[0].get_first_pcbm().isd_as
            req_pkt = self._build_packet(PT.PATH_MGMT, dst_ia=dst_ia,
                                         path=path, payload=seg_info)
            logging.info("Down-Segment request for different ISD, "
                         "forwarding request to CPS in %s via %s",
                         dst_ia, csegs[0].short_desc())
            self._send_to_next_hop(req_pkt, path.get_fwd_if())
        # If no core segment was available, add request to waiting targets.
        else:
            logging.info("Waiting for core segment to AS %s", dst_ia)
            self.waiting_targets.add((dst_ia, seg_info))
            # Ask for any segment to dst_isd
            self._query_master(PST.GENERIC, dst_ia.any_as())
