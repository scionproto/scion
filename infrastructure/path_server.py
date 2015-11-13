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
import copy
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
from lib.packet.path import UP_IOF
from lib.packet.path_mgmt import (
    PathRecordsReply,
    PathRecordsSync,
    PathSegmentInfo,
    RevocationInfo,
)
from lib.packet.scion import PacketType as PT, SCIONL4Packet
from lib.path_db import DBResult, PathSegmentDB
from lib.thread import thread_safety_net
from lib.types import PathMgmtType as PMT, PathSegmentType as PST, PayloadClass
from lib.util import (
    SCIONTime,
    sleep_interval,
    update_dict,
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
        self.down_segments = PathSegmentDB()
        self.core_segments = PathSegmentDB()  # Direction of the propagation.
        self.pending_down = {}  # Dict of pending DOWN _and_ UP_DOWN requests.
        self.pending_core = {}
        self.waiting_targets = set()  # Used when local PS doesn't have up-path.
        self.revocations = ExpiringDict(1000, 300)
        self.iftoken2seg = defaultdict(set)
        # Must be set in child classes:
        self._cached_seg_handler = None

        self.PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REQUEST: self.handle_path_request,
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

    def send_path_segments(self, pkt, paths):
        """
        Sends path-segments to requester (depending on Path Server's location)
        """
        rep_pkt = pkt.reversed_copy()
        seg_info = rep_pkt.get_payload()
        rep_pkt.set_payload(PathRecordsReply.from_values(seg_info, paths))
        (next_hop, port) = self.get_first_hop(rep_pkt)
        if next_hop is None:
            logging.error("Next hop is None for Interface %d",
                          rep_pkt.path.get_fwd_if())
            return
        logging.info(
            "Sending PATH_REPLY with %d path(s) for %s:%s-%s "
            "to:(%s-%s, %s:%s):\n  %s", len(paths),
            PST.to_str(seg_info.seg_type), seg_info.dst_isd,
            seg_info.dst_ad, rep_pkt.addrs.dst_isd, rep_pkt.addrs.dst_ad,
            rep_pkt.addrs.dst_addr, rep_pkt.l4_hdr.dst_port,
            "\n  ".join([pcb.short_desc() for pcb in paths]),
        )
        self.send(rep_pkt, next_hop, port)

    def dispatch_path_segment_record(self, pkt):
        """
        Dispatches path record packet.
        """
        type_map = {
            PST.UP: self._handle_up_segment_record,
            PST.DOWN: self._handle_down_segment_record,
            PST.UP_DOWN: self._handle_down_segment_record,
            PST.CORE: self._handle_core_segment_record,
        }
        payload = pkt.get_payload()
        handler = type_map.get(payload.info.seg_type)
        if handler is None:
            logging.error("Unsupported path record type: %s", payload)
            return
        handler(pkt)

    @abstractmethod
    def handle_path_request(self, path_request):
        """
        Handles all types of path request.
        """
        raise NotImplementedError

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
        logging.debug("Segment(s) stored in ZK: %s",
                      "\n".join([pcb.short_desc() for pcb in payload.pcbs]))

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
        self.core_ads = set()  # Set of core ADs only from local ISD.
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
        down_paths = self.down_segments(last_isd=self.topology.isd_id)
        logging.debug("Syncing with %s" % master)
        for seg_type, paths in [(PST.CORE, core_paths), (PST.DOWN, down_paths)]:
            for pcb in paths:
                tmp = (pcb.get_first_pcbm().isd_id, pcb.get_first_pcbm().ad_id,
                       pcb.get_last_pcbm().isd_id, pcb.get_last_pcbm().ad_id)
                # Send only one path for given (src, dst) pair.
                if tmp in seen_ads:
                    continue
                seen_ads.add(tmp)
                info = PathSegmentInfo.from_values(seg_type, *tmp)
                records = PathRecordsSync.from_values(info, [pcb])
                pkt = self._build_packet(payload=records)
                self._send_to_master(pkt)
                logging.debug('Master updated with path (%d) %s' %
                              (seg_type, tmp))

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
        Handle registration of a down path.
        """
        records = pkt.get_payload()
        from_master = (
            pkt.addrs.src_isd == self.addr.isd_id and
            pkt.addrs.src_ad == self.addr.ad_id and
            records.PAYLOAD_TYPE == PMT.REPLY)
        if not records.pcbs:
            return
        paths_to_propagate = []
        paths_to_master = []
        for pcb in records.pcbs:
            src_isd = pcb.get_first_pcbm().isd_id
            src_ad = pcb.get_first_pcbm().ad_id
            dst_ad = pcb.get_last_pcbm().ad_id
            dst_isd = pcb.get_last_pcbm().isd_id
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
                logging.info("Down-Segment registered: %s", pcb.short_desc())
                if res == DBResult.ENTRY_ADDED:
                    self._add_if_mappings(pcb)
            else:
                logging.info("Down-Segment already known: %s", pcb.short_desc())
        # For now we let every CPS know about all the down-paths within an ISD.
        # Also send paths to local master.
        # FIXME: putting all paths into single packet may be not a good decision
        if paths_to_propagate:
            records = PathRecordsReply.from_values(
                records.info, paths_to_propagate)
            pkt = self._build_packet(payload=records)
            # Now propagate paths to other core ADs (in the ISD).
            logging.debug("Propagate among core ADs")
            self._propagate_to_core_ads(pkt)
        # Send paths to local master.
        if (paths_to_master and not from_master and self._master_id and not
                self._is_master()):
            records = PathRecordsReply.from_values(records.info,
                                                   paths_to_master)
            pkt = self._build_packet(payload=records)
            self._send_to_master(pkt)
        # Serve pending requests.
        target = (dst_isd, dst_ad)
        if target in self.pending_down:
            segments_to_send = self.down_segments(last_isd=dst_isd,
                                                  last_ad=dst_ad)
            segments_to_send = segments_to_send[:self.MAX_SEG_NO]
            for pkt in self.pending_down[target]:
                self.send_path_segments(pkt, segments_to_send)
            del self.pending_down[target]

    def _handle_core_segment_record(self, pkt, from_zk=False):
        """
        Handle registration of a core path.
        """
        records = pkt.get_payload()
        from_master = (
            pkt.addrs.src_isd == self.addr.isd_id and
            pkt.addrs.src_ad == self.addr.ad_id and
            records.PAYLOAD_TYPE == PMT.REPLY)
        if not records.pcbs:
            return
        pcb_from_local_isd = True
        for pcb in records.pcbs:
            dst_ad = pcb.get_first_pcbm().ad_id
            dst_isd = pcb.get_first_pcbm().isd_id
            src_ad = pcb.get_last_pcbm().ad_id
            src_isd = pcb.get_last_pcbm().isd_id
            res = self.core_segments.update(pcb, first_isd=dst_isd,
                                            first_ad=dst_ad, last_isd=src_isd,
                                            last_ad=src_ad)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
                logging.info("Core-Path registered (from zk: %s): %s",
                             from_zk, pcb.short_desc())
            else:
                logging.info("Core-Path already known (from zk: %s): %s",
                             from_zk, pcb.short_desc())
            if dst_isd == self.topology.isd_id:
                self.core_ads.add((dst_isd, dst_ad))
            else:
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
        if self.waiting_targets:
            pcb = records.pcbs[0]
            path = pcb.get_path(reverse_direction=True)
            targets = copy.copy(self.waiting_targets)
            if_id = pcb.get_last_pcbm().hof.ingress_if
            for (target_isd, target_ad, seg_info) in targets:
                if target_isd == dst_isd:
                    req_pkt = self._build_packet(
                        PT.PATH_MGMT, payload=seg_info, path=path,
                        dst_isd=dst_isd, dst_ad=dst_ad)
                    logging.debug("Sending path request %s on newly learned "
                                  "path to (%d, %d)", seg_info, dst_isd, dst_ad)
                    self._send_to_next_hop(req_pkt, if_id)
                    self.waiting_targets.remove((target_isd, target_ad,
                                                 seg_info))

        # Serve pending core path requests.
        for target in [((src_isd, src_ad), (dst_isd, dst_ad)),
                       ((src_isd, src_ad), (dst_isd, 0))]:
            if self.pending_core:
                logging.debug("D01 Target: %s, pending_core: %s " %
                              (target, self.pending_core))
            if target in self.pending_core:
                segments_to_send = self.core_segments(first_isd=dst_isd,
                                                      first_ad=dst_ad or None,
                                                      last_isd=src_isd,
                                                      last_ad=src_ad)
                segments_to_send = segments_to_send[:self.MAX_SEG_NO]
                for pkt in self.pending_core[target]:
                    self.send_path_segments(pkt, segments_to_send)
                del self.pending_core[target]
                logging.debug("D02: %s removed from pending_core", target)

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

    def _propagate_to_core_ads(self, pkt, inter_isd=False):
        """
        Propagate 'pkt' to other core ADs.

        :param pkt: the packet to propagate (without path)
        :type pkt: lib.packet.packet_base.PacketBase
        :param inter_isd: whether the packet should be propagated across ISDs
        :type inter_isd: bool
        """
        for (isd, ad) in self.core_ads:
            if inter_isd or isd == self.topology.isd_id:
                cpaths = self.core_segments(first_isd=isd, first_ad=ad,
                                            last_isd=self.topology.isd_id,
                                            last_ad=self.topology.ad_id)
                if cpaths:
                    cpath = cpaths[0].get_path(reverse_direction=True)
                    pkt.path = cpath
                    pkt.addrs.dst_isd = isd
                    pkt.addrs.dst_ad = ad
                    pkt.addrs.dst_addr = PT.PATH_MGMT

                    logging.info("Sending packet to CPS in (%d, %d).", isd, ad)
                    self._send_to_next_hop(pkt, cpath.get_fwd_if())
                else:
                    logging.warning("Path to AD (%d, %d) not found.", isd, ad)

    def handle_path_request(self, pkt):
        seg_info = pkt.get_payload()
        seg_type = seg_info.seg_type
        dst_isd = seg_info.dst_isd
        dst_ad = seg_info.dst_ad
        logging.info("PATH_REQ received: type: %s, addr: (%d, %d)",
                     PST.to_str(seg_type), dst_isd, dst_ad)
        segments_to_send = []
        if seg_type == PST.UP:
            logging.error("CPS received up-segment request! This should not "
                          "happen")
            return
        if seg_type in [PST.DOWN, PST.UP_DOWN]:
            paths = self.down_segments(last_isd=dst_isd, last_ad=dst_ad)
            if paths:
                # We already have paths matching the request
                paths = paths[:self.MAX_SEG_NO]
                segments_to_send.extend(paths)
            elif dst_isd == self.topology.isd_id:
                update_dict(self.pending_down, (dst_isd, dst_ad), [pkt])
                logging.info("No down-path segment for (%d, %d), "
                             "request is pending.", dst_isd, dst_ad)
                if not self._is_master():
                    self._query_master(seg_type, dst_isd, dst_ad)
            else:
                # Destination is in a different ISD. Ask a CPS in a this ISD for
                # a down-path using the first available core path.
                update_dict(self.pending_down, (dst_isd, dst_ad), [pkt])
                cpaths = self.core_segments(first_isd=dst_isd,
                                            last_isd=self.topology.isd_id,
                                            last_ad=self.topology.ad_id)
                if cpaths:
                    path = cpaths[0].get_path(reverse_direction=True)
                    dst_isd = cpaths[0].get_first_pcbm().isd_id
                    dst_ad = cpaths[0].get_first_pcbm().ad_id
                    req_pkt = self._build_packet(
                        PT.PATH_MGMT, dst_isd=dst_isd, dst_ad=dst_ad,
                        path=path, payload=seg_info)
                    logging.info("Down-Segment request for different ISD. "
                                 "Forwarding request to CPS in (%d, %d).",
                                 dst_isd, dst_ad)
                    self._send_to_next_hop(req_pkt, path.get_fwd_if())
                # If no core_path was available, add request to waiting targets.
                else:
                    logging.info("Waiting for core path to target ISD (%d, %d)",
                                 dst_isd, dst_ad)
                    self.waiting_targets.add((dst_isd, dst_ad, seg_info))
                    if not self._is_master():
                        # Ask for any path to dst_isd
                        self._query_master(PST.CORE, dst_isd, 0)
        elif seg_type == PST.CORE:
            src_isd = seg_info.src_isd
            src_ad = seg_info.src_ad
            # Check if requester wants any path to ISD.
            if not dst_ad and not self._is_master():
                logging.warning("Request for ISD path and self is not master")
            key = ((src_isd, src_ad), (dst_isd, dst_ad))
            paths = self.core_segments(first_isd=dst_isd,
                                       first_ad=dst_ad or None,
                                       last_isd=src_isd,
                                       last_ad=src_ad)
            if paths:
                paths = paths[:self.MAX_SEG_NO]
                segments_to_send.extend(paths)
            else:
                update_dict(self.pending_core, key, [pkt])
                logging.info("No core-segment for (%d, %d) -> (%d, %d), "
                             "request is pending.", src_isd, src_ad,
                             dst_isd, dst_ad)
                if not self._is_master():
                    self._query_master(seg_type, dst_isd, dst_ad, src_isd,
                                       src_ad)
        else:
            logging.error("CPS received unsupported path request!.")
        if segments_to_send:
            self.send_path_segments(pkt, segments_to_send)


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
        self.up_segments = PathSegmentDB()
        self.pending_up = []  # List of pending UP requests.
        self._cached_seg_handler = self._handle_up_segment_record

    def _update_master(self):
        pass

    def _handle_up_segment_record(self, pkt, from_zk=False):
        """
        Handle Up Path registration from local BS or ZK's cache.

        :param pkt:
        :type pkt:
        """
        records = pkt.get_payload()
        if not records.pcbs:
            return
        for pcb in records.pcbs:
            res = self.up_segments.update(pcb, pcb.get_first_pcbm().isd_id,
                                          pcb.get_first_pcbm().ad_id,
                                          self.topology.isd_id,
                                          self.topology.ad_id)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
                logging.info("Up-Segment registered (from zk: %s): %s",
                             from_zk, pcb.short_desc())
        # Share Up Segment via ZK.
        if not from_zk:
            self._share_segments(pkt)
        # Sending pending targets to the core using first registered up-path.
        if self.waiting_targets:
            pcb = records.pcbs[0]
            path = pcb.get_path(reverse_direction=True)
            dst_isd = pcb.get_isd()
            dst_ad = pcb.get_first_pcbm().ad_id
            targets = copy.copy(self.waiting_targets)
            for (isd, ad, seg_info) in targets:
                req_pkt = self._build_packet(
                    PT.PATH_MGMT, dst_isd=dst_isd, dst_ad=dst_ad,
                    path=path, payload=seg_info)
                self._send_to_next_hop(req_pkt, path.get_fwd_if())
                logging.info("PATH_REQ sent using (first) registered up-path")
                self.waiting_targets.remove((isd, ad, seg_info))
        # Handling pending UP_PATH requests.
        for path_request in self.pending_up:
            self.send_path_segments(path_request,
                                    self.up_segments()[:self.MAX_SEG_NO])
        self.pending_up = []

    def _handle_down_segment_record(self, pkt):
        """
        :param pkt:
        :type pkt:
        """
        records = pkt.get_payload()
        if not records.pcbs:
            return
        for pcb in records.pcbs:
            src_isd = pcb.get_first_pcbm().isd_id
            src_ad = pcb.get_first_pcbm().ad_id
            dst_ad = pcb.get_last_pcbm().ad_id
            dst_isd = pcb.get_last_pcbm().isd_id
            res = self.down_segments.update(pcb, src_isd, src_ad,
                                            dst_isd, dst_ad)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)

        # serve pending requests
        target = (dst_isd, dst_ad)
        if target in self.pending_down:
            segments_to_send = self.down_segments(last_isd=dst_isd,
                                                  last_ad=dst_ad)
            segments_to_send = segments_to_send[:self.MAX_SEG_NO]
            for path_request in self.pending_down[target]:
                self.send_path_segments(path_request, segments_to_send)
            del self.pending_down[target]

    def _handle_core_segment_record(self, pkt):
        """
        Handle registration of a core path.

        :param pkt:
        :type pkt:
        """
        records = pkt.get_payload()
        if not records.pcbs:
            return
        for pcb in records.pcbs:
            # Core segments have down-path direction.
            src_ad = pcb.get_last_pcbm().ad_id
            src_isd = pcb.get_last_pcbm().isd_id
            dst_ad = pcb.get_first_pcbm().ad_id
            dst_isd = pcb.get_first_pcbm().isd_id
            res = self.core_segments.update(pcb, first_isd=dst_isd,
                                            first_ad=dst_ad, last_isd=src_isd,
                                            last_ad=src_ad)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
                logging.info("Core-Segment registered: %s", pcb.short_desc())
        # Serve pending core path requests.
        target = ((src_isd, src_ad), (dst_isd, dst_ad))
        if target in self.pending_core:
            segments_to_send = self.core_segments(first_isd=dst_isd,
                                                  first_ad=dst_ad,
                                                  last_isd=src_isd,
                                                  last_ad=src_ad)
            segments_to_send = segments_to_send[:self.MAX_SEG_NO]
            for path_request in self.pending_core[target]:
                self.send_path_segments(path_request, segments_to_send)
            del self.pending_core[target]

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

    def _request_paths_from_core(self, ptype, dst_isd, dst_ad,
                                 src_isd=None, src_ad=None):
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
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id
        seg_info = PathSegmentInfo.from_values(ptype, src_isd, src_ad, dst_isd,
                                               dst_ad)
        if not len(self.up_segments):
            if ptype == PST.DOWN:
                logging.info('Pending target added (%d, %d)', dst_isd, dst_ad)
                self.waiting_targets.add((dst_isd, dst_ad, seg_info))
            return
        logging.info('Requesting path from core: type: %s, addr: %d,%d',
                     PST.to_str(ptype), dst_isd, dst_ad)
        if ptype == PST.DOWN:
            # Take any path towards core.
            pcb = self.up_segments()[0]
        elif ptype == PST.CORE:
            # Request core AD that should have given core-path.
            pcbs = self.up_segments(first_isd=src_isd, first_ad=src_ad)
            if not pcbs:
                logging.warning("Core path (%d, %d)->(%d, %d) requested, "
                                "but up path to (%d, %d) not found." %
                                (src_isd, src_ad, dst_isd, dst_ad,
                                    src_isd, src_ad))
                return
            pcb = pcbs[0]
        else:
            logging.error("UP_PATH request to core.")
            return

        path = pcb.get_path(reverse_direction=True)
        up_seg_info = path.get_ofs_by_label(UP_IOF)[0]
        up_seg_info.up_flag = True
        req_pkt = self._build_packet(
            PT.PATH_MGMT, payload=seg_info, path=path, dst_isd=pcb.get_isd(),
            dst_ad=pcb.get_first_pcbm().ad_id)
        self._send_to_next_hop(req_pkt, path.get_fwd_if())

    def handle_path_request(self, pkt):
        """
        Handle all types of path request.

        :param pkt:
        :type pkt:
        """
        seg_info = pkt.get_payload()
        seg_type = seg_info.seg_type
        dst_isd = seg_info.dst_isd
        dst_ad = seg_info.dst_ad
        logging.info("PATH_REQ received: type: %s, addr: %d,%d",
                     PST.to_str(seg_type), dst_isd, dst_ad,)
        paths_to_send = []
        # Requester wants up-path.
        if seg_type in (PST.UP, PST.UP_DOWN):
            if len(self.up_segments):
                paths_to_send.extend(self.up_segments()[:self.MAX_SEG_NO])
            else:
                if seg_type == PST.UP_DOWN:
                    update_dict(self.pending_down, (dst_isd, dst_ad), [pkt])
                    self.waiting_targets.add((dst_isd, dst_ad, seg_info))
                self.pending_up.append(pkt)
                return
        # Requester wants down-path.
        if seg_type in (PST.DOWN, PST.UP_DOWN):
            paths = self.down_segments(last_isd=dst_isd, last_ad=dst_ad)
            if paths:
                paths_to_send.extend(paths[:self.MAX_SEG_NO])
            else:
                update_dict(self.pending_down, (dst_isd, dst_ad), [pkt])
                self._request_paths_from_core(PST.DOWN, dst_isd, dst_ad)
                logging.info("No downpath, request is pending.")
        # Requester wants core-path.
        if seg_type == PST.CORE:
            src_isd = seg_info.src_isd
            src_ad = seg_info.src_ad
            paths = self.core_segments(last_isd=src_isd, last_ad=src_ad,
                                       first_isd=dst_isd, first_ad=dst_ad)
            if paths:
                paths_to_send.extend(paths[:self.MAX_SEG_NO])
            else:
                update_dict(self.pending_core,
                            ((src_isd, src_ad), (dst_isd, dst_ad)), [pkt])
                self._request_paths_from_core(PST.CORE, dst_isd, dst_ad,
                                              src_isd, src_ad)
        if paths_to_send:
            self.send_path_segments(pkt, paths_to_send)


if __name__ == "__main__":
    main_wrapper(main_default, CorePathServer, LocalPathServer)
