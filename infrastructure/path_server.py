#!/usr/bin/python3
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
:mod:`path_server` --- SCION path server
========================================
"""
# Stdlib
import logging
import threading
from _collections import defaultdict
from abc import ABCMeta, abstractmethod

# External packages
from Crypto.Hash import SHA256
from external.expiring_dict import ExpiringDict

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.defines import PATH_SERVICE, SCION_UDP_PORT
from lib.errors import SCIONParseError
from lib.log import log_exception
from lib.main import main_default, main_wrapper
from lib.packet.host_addr import haddr_parse
from lib.packet.path_mgmt import (
    PathRecordsReply,
    PathRecordsSync,
    PathSegmentInfo,
    RevocationInfo,
)
from lib.packet.scion import PacketType as PT, SCIONL4Packet
from lib.packet.scion_addr import ISD_AD
from lib.path_db import DBResult, PathSegmentDB
from lib.thread import thread_safety_net
from lib.types import PathMgmtType as PMT, PathSegmentType as PST, PayloadClass
from lib.util import (
    SCIONTime,
    sleep_interval,
)
from lib.zookeeper import ZkNoConnection, ZkSharedCache, Zookeeper


class PathServer(SCIONElement, metaclass=ABCMeta):
    """
    The SCION Path Server.
    """
    SERVICE_TYPE = PATH_SERVICE
    MAX_SEG_NO = 5  # TODO: replace by config variable.
    # ZK path for incoming PATHs
    ZK_PATH_CACHE_PATH = "path_cache"
    # Number of tokens the PS checks when receiving a revocation.
    N_TOKENS_CHECK = 20

    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        # TODO replace by pathstore instance
        self.down_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO)
        # Core segments are in direction of the propagation.
        self.core_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO)
        self.pending_req = defaultdict(list)  # Dict of pending requests.
        self.waiting_targets = set()  # Used when l/cPS doesn't have up/dw-path.
        self.revocations = ExpiringDict(1000, 300)
        self.iftoken2seg = defaultdict(set)
        # Must be set in child classes:
        self._cached_seg_handler = None

        self.PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REQUEST: self.path_resolution,
                PMT.REPLY: self.dispatch_path_segment_record,
                PMT.REG: self.dispatch_path_segment_record,
                PMT.REVOCATION: self._handle_revocation,
                PMT.SYNC: self.dispatch_path_segment_record,
            },
        }

        if not is_sim:
            # Add more IPs here if we support dual-stack
            name_addrs = "\0".join([self.id, str(SCION_UDP_PORT),
                                    str(self.addr.host_addr)])
            self.zk = Zookeeper(
                self.topology.isd_id, self.topology.ad_id, PATH_SERVICE,
                name_addrs, self.topology.zookeepers)
            self.zk.retry("Joining party", self.zk.party_setup)
            self.path_cache = ZkSharedCache(self.zk, self.ZK_PATH_CACHE_PATH,
                                            self._cached_entries_handler)

    def worker(self):
        """
        Worker thread that takes care of reading shared paths from ZK, and
        handling master election for core servers.
        """
        worker_cycle = 1.0
        start = SCIONTime.get_time()
        while True:
            sleep_interval(start, worker_cycle, "cPS.worker cycle")
            start = SCIONTime.get_time()
            try:
                self.zk.wait_connected()
                self.path_cache.process()
                # Try to become a master.
                is_master = self.zk.get_lock(lock_timeout=0, conn_timeout=0)
                if is_master:
                    self.path_cache.expire(self.config.propagation_time * 10)
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')
                pass
            self._update_master()

    def _cached_entries_handler(self, raw_entries):
        """
        Handles cached through ZK entries, passed as a list.
        """
        for entry in raw_entries:
            try:
                pkt = SCIONL4Packet(raw=entry)
            except SCIONParseError:
                log_exception("Error parsing cached packet: %s" % entry,
                              level=logging.ERROR)
                continue
            try:
                pkt.parse_payload()
            except SCIONParseError:
                log_exception("Error parsing cached payload:\n%s" % pkt)
                continue
            self._cached_seg_handler(pkt, from_zk=True)

    @abstractmethod
    def _update_master(self):
        raise NotImplementedError

    def _add_if_mappings(self, pcb):
        """
        Add if revocation token to segment ID mappings.
        """
        segment_id = pcb.get_hops_hash()
        for ad in pcb.ads:
            self.iftoken2seg[ad.pcbm.ig_rev_token].add(segment_id)
            self.iftoken2seg[ad.eg_rev_token].add(segment_id)
            for pm in ad.pms:
                self.iftoken2seg[pm.ig_rev_token].add(segment_id)

    @abstractmethod
    def _handle_up_segment_record(self, records):
        """
        Handles Up Path registration from local BS.
        """
        raise NotImplementedError

    @abstractmethod
    def _handle_down_segment_record(self, records):
        """
        Handles registration of a down path.
        """
        raise NotImplementedError

    @abstractmethod
    def _handle_core_segment_record(self, records):
        """
        Handles a core_path record.
        """
        raise NotImplementedError

    def _handle_revocation(self, pkt):
        """
        Handles a revocation of a segment, interface or hop.

        :param pkt: The packet containing the revocation info.
        :type pkt: PathMgmtPacket
        """
        rev_info = pkt.get_payload()
        assert isinstance(rev_info, RevocationInfo)
        if hash(rev_info) in self.revocations:
            logging.debug("Already received revocation. Dropping...")
            return
        else:
            self.revocations[hash(rev_info)] = rev_info
            logging.debug("Received revocation from %s:\n%s",
                          pkt.addrs.get_src_addr(), rev_info)
        # Remove segments that contain the revoked interface.
        self._remove_revoked_segments(rev_info)

    def _remove_revoked_segments(self, rev_info):
        """
        Remove segments that contain a revoked interface. Checks 20 tokens in
        case previous revocations were missed by the PS.

        :param rev_info: The revocation info
        :type rev_info: RevocationInfo
        """
        rev_token = rev_info.rev_token
        for _ in range(self.N_TOKENS_CHECK):
            rev_token = SHA256.new(rev_token).digest()
            segments = self.iftoken2seg[rev_token]
            while segments:
                sid = segments.pop()
                # Delete segment from DB.
                self.down_segments.delete(sid)
                self.core_segments.delete(sid)
            if rev_token in self.iftoken2seg:
                del self.iftoken2seg[rev_token]

    def _send_to_next_hop(self, pkt, if_id):
        """
        Sends the packet to the next hop of the given if_id.
        :param if_id: The interface ID of the corresponding interface.
        :type if_id: int.
        """
        if if_id not in self.ifid2addr:
            logging.error("Interface ID %d not found in ifid2addr.", if_id)
            return
        next_hop = self.ifid2addr[if_id]
        self.send(pkt, next_hop)

    def _send_path_segments(self, pkt, up=None, core=None, down=None):
        """
        Sends path-segments to requester (depending on Path Server's location).
        """
        up = up or set()
        core = core or set()
        down = down or set()
        if not (up | core | down):
            logging.warning("No segments to send")
        rep_pkt = pkt.reversed_copy()
        rep_pkt.set_payload(PathRecordsReply.from_values(
            {PST.UP: up, PST.CORE: core, PST.DOWN: down}))
        rep_pkt.addrs.src_addr = self.addr.host_addr
        (next_hop, port) = self.get_first_hop(rep_pkt)
        if next_hop is None:
            logging.error("Next hop is None for Interface %d",
                          rep_pkt.path.get_fwd_if())
            return
        logging.info(
            "Sending PATH_REPLY with %d segment(s) to:(%s-%s, %s:%s):\n  %s",
            len(up | core | down), rep_pkt.addrs.dst_isd, rep_pkt.addrs.dst_ad,
            rep_pkt.addrs.dst_addr, rep_pkt.l4_hdr.dst_port,
            "\n  ".join([pcb.short_desc() for pcb in (up | core | down)]),
        )
        self.send(rep_pkt, next_hop, port)

    def _handle_pending_requests(self, added):
        for dst_isd, dst_ad in added:
            to_remove = []
            # Serve pending requests.
            for pkt in self.pending_req[(dst_isd, dst_ad)]:
                if self.path_resolution(pkt, new_request=False):
                    to_remove.append(pkt)
            # Clean state.
            for pkt in to_remove:
                self.pending_req[(dst_isd, dst_ad)].remove(pkt)
            if not self.pending_req[(dst_isd, dst_ad)]:
                del self.pending_req[(dst_isd, dst_ad)]

    def dispatch_path_segment_record(self, pkt):
        """
        Dispatches path record packet.
        """
        # FIXME(PSz): ugly for now
        handlers = []
        payload = pkt.get_payload()
        if payload.pcbs[PST.UP]:
            handlers.append(self._handle_up_segment_record)
        if payload.pcbs[PST.CORE]:
            handlers.append(self._handle_core_segment_record)
        if payload.pcbs[PST.DOWN]:
            handlers.append(self._handle_down_segment_record)
        if not handlers:
            logging.error("Unsupported path record type: %s", payload)
            return

        added = set()
        for handler in handlers:
            added.update(handler(pkt))
        # Handling pending request, basing on added segments.
        self._handle_pending_requests(added)

    @abstractmethod
    def path_resolution(self, path_request):
        """
        Handles all types of path request.
        """
        raise NotImplementedError

    def _handle_waiting_targets(self, path):
        if not self.waiting_targets:
            return
        dst_isd, dst_ad = path.get_first_isd_ad()
        path = path.get_path(reverse_direction=True)
        while self.waiting_targets:
            isd, ad, seg_info = self.waiting_targets.pop()
            req_pkt = self._build_packet(
                PT.PATH_MGMT, dst_isd=dst_isd, dst_ad=dst_ad,
                path=path, payload=seg_info)
            self._send_to_next_hop(req_pkt, path.get_fwd_if())
            logging.info("PATH_REQ sent using (first) registered up-path")

    def _share_segments(self, pkt):
        """
        Share path segments (via ZK) with other path servers.
        """
        pkt_packed = pkt.pack()
        pkt_hash = SHA256.new(pkt_packed).hexdigest()
        try:
            self.path_cache.store("%s-%s" % (pkt_hash, SCIONTime.get_time()),
                                  pkt_packed)
        except ZkNoConnection:
            logging.warning("Unable to store segment in shared path: "
                            "no connection to ZK")
            return
        payload = pkt.get_payload()
        pcbs = []
        for tmp in payload.pcbs.values():
            pcbs.extend(tmp)
        logging.debug("Segment(s) stored in ZK: %s",
                      "\n".join([pcb.short_desc() for pcb in pcbs]))

    def run(self):
        """
        Run an instance of the Path Server.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="PS.worker", daemon=True).start()

        super().run()


class CorePathServer(PathServer):
    """
    SCION Path Server in a core AD. Stores intra ISD down-paths as well as core
    paths and forwards inter-ISD path requests to the corresponding path server.
    """
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
                records = PathRecordsSync.from_values({seg_type: [pcb]})
                pkt = self._build_packet(payload=records)
                self._send_to_master(pkt)
                logging.debug('Master updated with path (%d) %s' %
                              (seg_type, key))

    def _is_master(self):
        """
        Return True when instance is master Core Path Server, False otherwise.
        """
        return self._master_id == str(self.addr.host_addr)

    def _handle_up_segment_record(self, pkt):
        """

        """
        logging.error("Core Path Server received up-path record!")

    def _handle_down_segment_record(self, pkt):
        """
        Handle registration of a down path. Return a set of added destinations.
        """
        added = set()
        records = pkt.get_payload()
        if not records.pcbs[PST.DOWN]:
            return added
        from_master = (
            pkt.addrs.src_isd == self.addr.isd_id and
            pkt.addrs.src_ad == self.addr.ad_id and
            records.PAYLOAD_TYPE == PMT.REPLY)
        paths_to_propagate = []
        paths_to_master = []
        for pcb in records.pcbs[PST.DOWN]:
            src_isd, src_ad = pcb.get_first_isd_ad()
            dst_isd, dst_ad = pcb.get_last_isd_ad()
            res = self.down_segments.update(pcb, src_isd, src_ad,
                                            dst_isd, dst_ad)
            if (dst_isd == pkt.addrs.src_isd and dst_ad == pkt.addrs.src_ad):
                # Only propagate this path if it was registered with us by the
                # down-stream AD.
                paths_to_propagate.append(pcb)
            if (src_isd == dst_isd == self.addr.isd_id):
                # Master replicates all seen down-paths from ISD.
                paths_to_master.append(pcb)
            if res != DBResult.NONE:
                if res == DBResult.ENTRY_ADDED:
                    self._add_if_mappings(pcb)
                    added.add((dst_isd, dst_ad))
                    logging.info("Down-Seg registered: %s", pcb.short_desc())
            else:
                logging.info("Down-Segment already known: %s", pcb.short_desc())
        # For now we let every CPS know about all the down-paths within an ISD.
        # Also send paths to local master.
        if paths_to_propagate:
            recs = PathRecordsReply.from_values({PST.DOWN: paths_to_propagate})
            # Now propagate paths to other core ADs (in the ISD).
            logging.debug("Propagate among core ADs")
            self._propagate_to_core_ads(recs)
        # Send paths to local master.
        if (paths_to_master and not from_master and not self._is_master()):
            rep_recs = PathRecordsReply.from_values(
                {PST.DOWN: paths_to_master})
            pkt = self._build_packet(payload=rep_recs)
            self._send_to_master(pkt)
        return added

    def _handle_core_segment_record(self, pkt, from_zk=False):
        """
        Handle registration of a core path. Return a set of added destinations.
        """
        added = set()
        records = pkt.get_payload()
        if not records.pcbs[PST.CORE]:
            return added
        from_master = (
            pkt.addrs.src_isd == self.addr.isd_id and
            pkt.addrs.src_ad == self.addr.ad_id and
            records.PAYLOAD_TYPE == PMT.REPLY)
        pcb_from_local_isd = True
        for pcb in records.pcbs[PST.CORE]:
            src_isd, src_ad = pcb.get_last_isd_ad()
            dst_isd, dst_ad = pcb.get_first_isd_ad()
            res = self.core_segments.update(pcb, first_isd=dst_isd,
                                            first_ad=dst_ad, last_isd=src_isd,
                                            last_ad=src_ad)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
                added.add((dst_isd, dst_ad))
                if dst_isd != self.addr.isd_id:
                    # Mark that a segment to remote ISD was added.
                    added.add((dst_isd, 0))
                logging.info("Core-Path registered (from zk: %s): %s",
                             from_zk, pcb.short_desc())
            else:
                logging.info("Core-Path already known (from zk: %s): %s",
                             from_zk, pcb.short_desc())
            if dst_isd != self.topology.isd_id:
                pcb_from_local_isd = False
        if not from_zk and not from_master and records.PAYLOAD_TYPE != PMT.SYNC:
            # Share segments via ZK.
            if pcb_from_local_isd:
                self._share_segments(pkt)
            # Send segments to master.
            elif self._master_id and not self._is_master():
                self._send_to_master(pkt)
        # Send pending requests that couldn't be processed due to the lack of
        # a core path to the destination PS.
        self._handle_waiting_targets(records.pcbs[PST.CORE][0])
        return added

    def _send_to_master(self, pkt):
        """
        Send 'pkt' to a master.
        """
        master = self._master_id
        if not master:
            logging.warning("_send_to_master(): _master_id not set.")
            return
        pkt.addrs.src_isd = pkt.addrs.dst_isd = self.addr.isd_id
        pkt.addrs.src_ad = pkt.addrs.dst_ad = self.addr.ad_id
        pkt.addrs.src_addr = self.addr.host_addr
        pkt.addrs.dst_addr = haddr_parse("IPV4", master)
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
        pkt = self._build_packet(payload=info)
        logging.debug("Asking master for path (%d): (%d, %d) -> (%d, %d)" %
                      (seg_type, src_isd, src_ad, dst_isd, dst_ad))
        self._send_to_master(pkt)

    def _propagate_to_core_ads(self, rep_recs):
        """
        Propagate 'pkt' to other core ADs.

        :param pkt: the packet to propagate (without path)
        :type pkt: lib.packet.packet_base.PacketBase
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
                logging.info("Path propagated to CPS in (%d, %d).\n", isd, ad)
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
                logging.warning("Handling pending request and needed seg"
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
        core_seg = set(self.core_segments(first_isd=dst_isd,
                                          first_ad=dst_ad or None,
                                          last_isd=my_isd, last_ad=my_ad))
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
            logging.info("Down-Segment request for different ISD."
                         "Forwarding request to CPS in (%d, %d).",
                         dst_isd, dst_ad)
            self._send_to_next_hop(req_pkt, path.get_fwd_if())
        # If no core_path was available, add request to waiting targets.
        else:
            logging.info("Waiting for core path to AS (%d, %d)",
                         dst_isd, dst_ad)
            self.waiting_targets.add((dst_isd, dst_ad, seg_info))
            # Ask for any path to dst_isd
            self._query_master(PST.GENERIC, dst_isd, 0)


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

        :param pkt:
        :type pkt:
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

        :param pkt:
        :type pkt:
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

        dst_is_core = dst in self._core_ads[dst.isd]
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
        if dst_in_local_isd:
            # Dst in local ISD. First check whether DST is a (super)-parent.
            up_seg.update(self.up_segments(first_isd=dst_isd, first_ad=dst_ad))
        # Check whether dst is known core AS.
        for cseg in self.core_segments(first_isd=dst_isd, first_ad=dst_ad):
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

        :param ptype:
        :type ptype:
        :param dst_isd:
        :type dst_isd:
        :param dst_ad:
        :type dst_ad:
        :param src_isd:
        :type src_isd:
        :param src_ad:
        :type src_ad:
        """
        src_isd, src_ad = self.addr.get_isd_ad()
        seg_info = PathSegmentInfo.from_values(PST.GENERIC, src_isd, src_ad,
                                               dst_isd, dst_ad)
        if not len(self.up_segments()):
            logging.info('Pending target added (%d, %d)', dst_isd, dst_ad)
            self.waiting_targets.add((dst_isd, dst_ad, seg_info))
            return

        logging.info('Requesting core for: %d,%d', dst_isd, dst_ad)
        # PSz: for multipath it makes sense to query with multiple core ASes
        pcb = self.up_segments()[0]
        path = pcb.get_path(reverse_direction=True)
        req_pkt = self._build_packet(PT.PATH_MGMT, payload=seg_info, path=path,
                                     dst_isd=pcb.get_isd(),
                                     dst_ad=pcb.get_first_pcbm().ad_id)
        self._send_to_next_hop(req_pkt, path.get_fwd_if())

if __name__ == "__main__":
    main_wrapper(main_default, CorePathServer, LocalPathServer)
