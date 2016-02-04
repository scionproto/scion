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
:mod:`base` --- Base path server
================================
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
from lib.packet.path_mgmt import (
    PathRecordsReply,
    RevocationInfo,
)
from lib.packet.scion import PacketType as PT, SCIONL4Packet
from lib.path_db import PathSegmentDB
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

    def _handle_pending_requests(self, dst_isd, dst_ad):
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
        for dst_isd, dst_ad in added:
            self._handle_pending_requests(dst_isd, dst_ad)
            self._handle_pending_requests(dst_isd, 0)

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
