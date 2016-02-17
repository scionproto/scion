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
from collections import defaultdict, deque

# SCION
from infrastructure.path_server.base import PathServer
from lib.packet.host_addr import haddr_parse
from lib.packet.path_mgmt import (
    PathRecordsReply,
    PathRecordsSync,
    PathSegmentInfo,
)
from lib.packet.scion import PacketType as PT
from lib.packet.scion_addr import ISD_AD
from lib.path_db import DBResult
from lib.types import PathMgmtType as PMT, PathSegmentType as PST
from lib.zookeeper import ZkNoConnection


class CorePathServer(PathServer):
    """
    SCION Path Server in a core AD. Stores intra ISD down-paths as well as core
    paths and forwards inter-ISD path requests to the corresponding path server.
    """
    PROP_LIMIT = 5  # Max number of segments per propagation packet

    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        # Sanity check that we should indeed be a core path server.
        assert self.topology.is_core_ad, "This shouldn't be a core PS!"
        self._master_id = None  # Address of master core Path Server.
        self._cached_seg_handler = self._handle_core_segment_record
        self._segs_to_master = deque()
        self._segs_to_prop = deque()

    def _update_master(self):
        """
        Read master's address from shared lock, and if new master is elected
        sync it with paths.
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
        Feed newly-elected master with paths.
        """
        # TODO(PSz): consider mechanism for avoiding a registration storm.
        master = self._master_id
        if not master or self._is_master():
            logging.warning('Sync abandoned: master not set or I am a master')
            return
        seen_ads = set()
        # Get core-segments from remote ISDs.
        # FIXME(PSz): quite ugly for now.
        core_paths = [r['record'].pcb for r in self.core_segments._db
                      if r['first_isd'] != self.topology.isd_id]
        # Get down-segments from local ISD.
        down_paths = self.down_segments(full=True, last_isd=self.addr.isd_id)
        logging.debug("Syncing with %s" % master)
        for seg_type, paths in [(PST.CORE, core_paths), (PST.DOWN, down_paths)]:
            for pcb in paths:
                key = (pcb.get_first_pcbm().isd_id, pcb.get_first_pcbm().ad_id,
                       pcb.get_last_pcbm().isd_id, pcb.get_last_pcbm().ad_id)
                # Send only one path for given (src, dst) pair.
                if key in seen_ads:
                    continue
                seen_ads.add(key)
                self._segs_to_prop.append((seg_type, pcb))
        for seg in self.sibra_segments():
            self._segs_to_prop.append((PST.SIBRA, seg))

    def _is_master(self):
        """
        Return True when instance is master Core Path Server, False otherwise.
        """
        return self._master_id == str(self.addr.host_addr)

    def _handle_up_segment_record(self, pkt):
        logging.error("Core Path Server received up-path record!")

    def _handle_down_segment_record(self, pkt):
        """
        Handle registration of a down path. Return a set of added destinations.
        """
        added = set()
        records = pkt.get_payload()
        if not records.pcbs[PST.DOWN]:
            return added
        pkt_src = ISD_AD(pkt.addrs.src_isd, pkt.addrs.src_ad)
        from_master = self._from_master(pkt)
        for pcb in records.pcbs[PST.DOWN]:
            added.update(self._add_down_segment(pkt_src, pcb, from_master))
        return added

    def _add_down_segment(self, pkt_src, pcb, from_master):
        src = pcb.get_first_isd_ad()
        dst = pcb.get_last_isd_ad()
        added = set()
        res = self.down_segments.update(pcb, src.isd, src.ad, dst.isd, dst.ad)
        if res == DBResult.NONE:
            logging.info("Down-Segment already known: %s", pcb.short_desc())
        elif res == DBResult.ENTRY_ADDED:
            self._add_if_mappings(pcb)
            added.add(dst)
            logging.info("Down-Seg registered: %s", pcb.short_desc())
        if dst == pkt_src:
            # If this path was registered with us by the down-stream AD,
            # propagate to all other core ADs within this ISD.
            self._segs_to_prop.append((PST.DOWN, pcb))
        if (src.isd == dst.isd == self.addr.isd_id and not from_master):
            # Master replicates all seen down-paths from ISD.
            self._segs_to_master.append((PST.DOWN, pcb))
        return added

    def _handle_core_segment_record(self, pkt, from_zk=False):
        """
        Handle registration of a core path. Return a set of added destinations.
        """
        added = set()
        records = pkt.get_payload()
        if not records.pcbs[PST.CORE]:
            return added
        from_master = self._from_master(pkt)
        # Does this packet contain only PCBs from the local ISD?
        # FIXME(kormat): this logic isn't good. We should switch to sharing
        # segments instead of packets.
        pcb_from_local_isd = True
        for pcb in records.pcbs[PST.CORE]:
            pcb_added, pcb_local = self._add_core_segment(
                pcb, from_master, from_zk)
            added.update(pcb_added)
            pcb_from_local_isd &= pcb_local
        if not from_zk and not from_master and records.PAYLOAD_TYPE != PMT.SYNC:
            if pcb_from_local_isd:
                # Packet contains only local PCBs, share via ZK.
                self._share_segments(pkt)
            # Send segments to master.
            elif self._master_id and not self._is_master():
                self._send_to_master(records)
        # Send pending requests that couldn't be processed due to the lack of
        # a core path to the destination PS.
        self._handle_waiting_targets(records.pcbs[PST.CORE][0])
        return added

    def _add_core_segment(self, pcb, from_master, from_zk):
        src = pcb.get_last_isd_ad()
        dst = pcb.get_first_isd_ad()
        added = set()
        res = self.core_segments.update(
            pcb, first_isd=dst.isd, first_ad=dst.ad,
            last_isd=src.isd, last_ad=src.ad)
        if res == DBResult.ENTRY_ADDED:
            self._add_if_mappings(pcb)
            added.add(dst)
            if dst.isd != self.addr.isd_id:
                # Mark that a segment to remote ISD was added.
                added.add((dst.isd, 0))
            logging.info("Core-Path registered (from zk: %s): %s",
                         from_zk, pcb.short_desc())
        else:
            logging.info("Core-Path already known (from zk: %s): %s",
                         from_zk, pcb.short_desc())
        return added, dst.isd == self.topology.isd_id

    def _handle_sibra_segment_record(self, pkt):
        records = pkt.get_payload()
        pkt_src = ISD_AD(pkt.addrs.src_isd, pkt.addrs.src_ad)
        from_master = self._from_master(pkt)
        for seg in records.sibra_segs:
            self._add_sibra_segment(seg)
            if from_master:
                continue
            if seg.src == pkt_src:
                # If this path was registered with us by the down-stream AD,
                # propagate to all other core ADs within this ISD.
                self._segs_to_prop.append((PST.SIBRA, seg))
            if seg.src.isd == seg.dst.isd == self.addr.isd_id:
                # Master gets a copy of all seen local SIBRA paths.
                self._segs_to_master.append((PST.SIBRA, seg))
        return set()

    def _from_master(self, pkt):
        pld = pkt.get_payload()
        return (pkt.addrs.src_isd == self.addr.isd_id and
                pkt.addrs.src_ad == self.addr.ad_id and
                pld.PAYLOAD_TYPE == PMT.REPLY)

    def _propagate_and_sync(self):
        if self._segs_to_prop:
            logging.info("Propagating %d segment(s) to other core ADs",
                         len(self._segs_to_prop))
        for pcbs in self._gen_prop_recs(self._segs_to_prop):
            self._propagate_to_core_ads(self._build_prop_recs(pcbs))
        if self._is_master():
            self._segs_to_master.clear()
            return
        if self._segs_to_master:
            logging.info("Propagating %d segment(s) to master PS",
                         len(self._segs_to_master))
        for pcbs in self._gen_prop_recs(self._segs_to_master):
            self._send_to_master(self._build_prop_recs(pcbs, sync=True))

    def _gen_prop_recs(self, queue):
        count = 0
        pcbs = defaultdict(list)
        while queue:
            count += 1
            type_, pcb = queue.popleft()
            pcbs[type_].append(pcb)
            if count >= self.PROP_LIMIT:
                yield(pcbs)
                count = 0
                pcbs = defaultdict(list)
        if pcbs:
            yield(pcbs)

    def _build_prop_recs(self, pcbs, sync=False):
        cls_ = PathRecordsReply
        if sync:
            cls_ = PathRecordsSync
        return cls_.from_values({
            PST.UP: pcbs[PST.UP], PST.DOWN: pcbs[PST.DOWN],
            PST.CORE: pcbs[PST.CORE]}, pcbs[PST.SIBRA],
        )

    def _send_to_master(self, pld):
        """
        Send the payload to the master PS.
        """
        master = self._master_id
        if not master:
            logging.warning("_send_to_master(): _master_id not set.")
            return
        pkt = self._build_packet(haddr_parse("IPV4", master), payload=pld)
        self.send(pkt, master)
        logging.debug("Packet sent to master %s", master)

    def _query_master(self, seg_type, dst_isd, dst_ad, src_isd=None,
                      src_ad=None):
        """
        Query master for a path.
        """
        if self._is_master():
            logging.debug("I'm master, query abandoned.")
            return
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id

        info = PathSegmentInfo.from_values(seg_type, src_isd, src_ad, dst_isd,
                                           dst_ad)
        logging.debug("Asking master for path (%d): (%d, %d) -> (%d, %d)" %
                      (seg_type, src_isd, src_ad, dst_isd, dst_ad))
        self._send_to_master(info)

    def _propagate_to_core_ads(self, rep_recs):
        """
        Propagate 'pkt' to other core ADs.
        """
        for (isd, ad) in self._core_ads[self.topology.isd_id]:
            if (isd, ad) == self.addr.get_isd_ad():
                continue
            cpaths = self.core_segments(first_isd=isd, first_ad=ad,
                                        last_isd=self.topology.isd_id,
                                        last_ad=self.topology.ad_id)
            if cpaths:
                cpath = cpaths[0].get_path(reverse_direction=True)
                pkt = self._build_packet(PT.PATH_MGMT, dst_isd=isd, dst_ad=ad,
                                         path=cpath, payload=rep_recs)
                self._send_to_next_hop(pkt, cpath.get_fwd_if())
            else:
                logging.warning("Path to AD (%d, %d) not found.", isd, ad)

    def path_resolution(self, pkt, new_request=True):
        """
        Handle generic type of a path request.
        new_request informs whether a pkt is a new request (True), or is a
        pending request (False).
        Return True when resolution succeeded, False otherwise.
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
        dst_is_core = dst in self._core_ads[dst.isd] or not dst.ad
        if dst_is_core:
            core_seg = self._resolve_core(pkt, dst.isd, dst.ad, new_request)
            down_seg = set()
        else:
            core_seg, down_seg = self._resolve_not_core(pkt, dst.isd, dst.ad,
                                                        new_request)

        if not (core_seg | down_seg):
            if new_request:
                logging.debug("Segs to %d,%d not found." % dst)
            else:
                # That could happend when a needed segment has expired.
                logging.warning("Handling pending request and needed segment "
                                "is missing. Shouldn't be here (too often).")
            return False

        logging.debug("Sending segments to %d,%d" % dst)
        self._send_path_segments(pkt, None, core_seg, down_seg)
        return True

    def _resolve_core(self, pkt, dst_isd, dst_ad, new_request):
        """
        Dst is core AS.
        """
        my_isd, my_ad = self.addr.get_isd_ad()
        params = {"first_isd": dst_isd, "last_isd": my_isd, "last_ad": my_ad}
        if dst_ad:
            # dst_ad=0 means any core AS in the specified ISD, so only
            # filter on the remote AS if it isn't 0
            params["first_ad"] = dst_ad
        core_seg = set(self.core_segments(**params))
        if not core_seg and new_request:
            # Segments not found and it is a neq request.
            self.pending_req[(dst_isd, dst_ad)].append(pkt)
            # If dst is in remote ISD then a segment may be kept by master.
            if dst_isd != self.addr.isd_id:
                self._query_master(PST.GENERIC, dst_isd, dst_ad)
        return core_seg

    def _resolve_not_core(self, pkt, dst_isd, dst_ad, new_request):
        """
        Dst is regular AS.
        """
        core_seg = set()
        down_seg = set()
        my_isd, my_ad = self.addr.get_isd_ad()
        # Check if there exists down-seg to dst.
        tmp_down_seg = self.down_segments(last_isd=dst_isd, last_ad=dst_ad)
        if not tmp_down_seg and new_request:
            self._resolve_not_core_failed(pkt, dst_isd, dst_ad)

        for dseg in tmp_down_seg:
            isd, ad = dseg.get_first_isd_ad()
            # Check whether it is a direct down segment.
            if (isd, ad) == self.addr.get_isd_ad():
                down_seg.add(dseg)
                continue

            # Now try core segments that connect to down segment.
            tmp_core_seg = self.core_segments(first_isd=isd, first_ad=ad,
                                              last_isd=my_isd, last_ad=my_ad)
            if not tmp_core_seg and new_request:
                # Core segment not found and it is a new request.
                self.pending_req[(isd, ad)].append(pkt)
                if dst_isd != self.addr.isd_id:  # Master may know a segment.
                    self._query_master(PST.GENERIC, isd, ad)
            elif tmp_core_seg:
                down_seg.add(dseg)
                core_seg.update(tmp_core_seg)
        return core_seg, down_seg

    def _resolve_not_core_failed(self, pkt, dst_isd, dst_ad):
        """
        Execute after _resolve_not_core() cannot resolve a new request, due to
        lack of corresponding down segment(s).
        This must not be executed for a pending request.
        """
        self.pending_req[(dst_isd, dst_ad)].append(pkt)
        if dst_isd == self.addr.isd_id:
            # Master may know down segment as dst is in local ISD.
            self._query_master(PST.GENERIC, dst_isd, dst_ad)
            return

        # Dst is in a remote ISD, ask any AS from there.
        csegs = self.core_segments(first_isd=dst_isd,
                                   last_isd=self.topology.isd_id,
                                   last_ad=self.topology.ad_id)
        seg_info = pkt.get_payload()
        if csegs:
            path = csegs[0].get_path(reverse_direction=True)
            dst_isd, dst_ad = csegs[0].get_first_isd_ad()
            req_pkt = self._build_packet(
                PT.PATH_MGMT, dst_isd=dst_isd, dst_ad=dst_ad,
                path=path, payload=seg_info)
            logging.info("Down-Segment request for different ISD, "
                         "forwarding request to CPS in (%d, %d) via %s",
                         dst_isd, dst_ad, csegs[0].short_desc())
            self._send_to_next_hop(req_pkt, path.get_fwd_if())
        # If no core_path was available, add request to waiting targets.
        else:
            logging.info("Waiting for core path to AS (%d, %d)",
                         dst_isd, dst_ad)
            self.waiting_targets.add((dst_isd, dst_ad, seg_info))
            # Ask for any path to dst_isd
            self._query_master(PST.GENERIC, dst_isd, 0)
