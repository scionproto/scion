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
from _collections import defaultdict, deque
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
from lib.packet.pcb import PathSegment
from lib.packet.scion import PacketType as PT
from lib.path_db import DBResult, PathSegmentDB
from lib.thread import thread_safety_net
from lib.types import PathMgmtType as PMT, PathSegmentType as PST, PayloadClass
from lib.util import Raw, SCIONTime, sleep_interval
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
    # Max number of segments per propagation packet
    PROP_LIMIT = 5
    # Max number of segments per ZK cache entry
    ZK_SHARE_LIMIT = 10

    def __init__(self, server_id, conf_dir, is_sim=False):
        """
        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param bool is_sim: running on simulator
        """
        super().__init__(server_id, conf_dir, is_sim=is_sim)
        self.down_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO)
        self.core_segments = PathSegmentDB(max_res_no=self.MAX_SEG_NO)
        self.pending_req = defaultdict(list)  # Dict of pending requests.
        # Used when l/cPS doesn't have up/dw-path.
        self.waiting_targets = defaultdict(list)
        self.revocations = ExpiringDict(1000, 300)
        self.iftoken2seg = defaultdict(set)
        self.PLD_CLASS_MAP = {
            PayloadClass.PATH: {
                PMT.REQUEST: self.path_resolution,
                PMT.REPLY: self.handle_path_segment_record,
                PMT.REG: self.handle_path_segment_record,
                PMT.REVOCATION: self._handle_revocation,
                PMT.SYNC: self.handle_path_segment_record,
            },
        }
        self._segs_to_zk = deque()
        if is_sim:
            return
        # Add more IPs here if we support dual-stack
        name_addrs = "\0".join([self.id, str(SCION_UDP_PORT),
                                str(self.addr.host)])
        self.zk = Zookeeper(self.topology.isd_as, PATH_SERVICE, name_addrs,
                            self.topology.zookeepers)
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
            self._propagate_and_sync()

    def _cached_entries_handler(self, raw_entries):
        """
        Handles cached through ZK entries, passed as a list.
        """
        count = 0
        for raw in raw_entries:
            data = Raw(raw)
            while data:
                type_ = data.pop(1)
                try:
                    pcb = PathSegment(data.get())
                except SCIONParseError:
                    log_exception("Error parsing cached pcb",
                                  level=logging.ERROR)
                    continue
                data.pop(len(pcb))
                count += 1
                self._dispatch_segment_record(type_, pcb, from_zk=True)
        if count:
            logging.debug("Processed %s PCBs from ZK", count)

    def _update_master(self):
        pass

    def _add_if_mappings(self, pcb):
        """
        Add if revocation token to segment ID mappings.
        """
        segment_id = pcb.get_hops_hash()
        for asm in pcb.ases:
            self.iftoken2seg[asm.pcbm.ig_rev_token].add(segment_id)
            self.iftoken2seg[asm.eg_rev_token].add(segment_id)
            for pm in asm.pms:
                self.iftoken2seg[pm.ig_rev_token].add(segment_id)

    @abstractmethod
    def _handle_up_segment_record(self, pcb, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def _handle_down_segment_record(self, pcb, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def _handle_core_segment_record(self, pcb, **kwargs):
        raise NotImplementedError

    def _add_segment(self, pcb, seg_db, name):
        res = seg_db.update(pcb)
        if res == DBResult.ENTRY_ADDED:
            self._add_if_mappings(pcb)
            logging.info("%s-Segment registered: %s", name, pcb.short_desc())
            return True
        elif res == DBResult.ENTRY_UPDATED:
            logging.debug("%s-Segment updated: %s", name, pcb.short_desc())
        return False

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
                          pkt.addrs.src, rev_info)
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
            return
        seg_req = pkt.get_payload()
        rep_pkt = pkt.reversed_copy()
        rep_pkt.set_payload(PathRecordsReply.from_values(
            {PST.UP: up, PST.CORE: core, PST.DOWN: down},
        ))
        rep_pkt.addrs.src.host = self.addr.host
        next_hop, port = self.get_first_hop(rep_pkt)
        if next_hop is None:
            logging.error("Next hop is None for Interface %s",
                          rep_pkt.path.get_fwd_if())
            return
        logging.info(
            "Sending PATH_REPLY with %d segment(s) to:%s "
            "port:%s in response to: %s", len(up | core | down),
            rep_pkt.addrs.dst, rep_pkt.l4_hdr.dst_port, seg_req.short_desc()
        )
        self.send(rep_pkt, next_hop, port)

    def _handle_pending_requests(self, dst_ia, sibra):
        to_remove = []
        key = dst_ia, sibra
        # Serve pending requests.
        for pkt in self.pending_req[key]:
            if self.path_resolution(pkt, new_request=False):
                to_remove.append(pkt)
        # Clean state.
        for pkt in to_remove:
            self.pending_req[key].remove(pkt)
        if not self.pending_req[key]:
            del self.pending_req[key]

    def handle_path_segment_record(self, pkt):
        seg_rec = pkt.get_payload()
        params = self._dispatch_params(pkt)
        added = set()
        for type_, pcbs in seg_rec.pcbs.items():
            for pcb in pcbs:
                added.update(
                    self._dispatch_segment_record(type_, pcb, **params))
        # Handling pending requests, basing on added segments.
        for dst_ia, sibra in added:
            self._handle_pending_requests(dst_ia, sibra)

    def _dispatch_segment_record(self, type_, seg, **kwargs):
        handle_map = {
            PST.UP: self._handle_up_segment_record,
            PST.CORE: self._handle_core_segment_record,
            PST.DOWN: self._handle_down_segment_record,
        }
        return handle_map[type_](seg, **kwargs)

    def _dispatch_params(self, pkt):
        return {}

    def _propagate_and_sync(self):
        self._share_via_zk()

    def _gen_prop_recs(self, queue, limit=PROP_LIMIT):
        count = 0
        pcbs = defaultdict(list)
        while queue:
            count += 1
            type_, pcb = queue.popleft()
            pcbs[type_].append(pcb)
            if count >= limit:
                yield(pcbs)
                count = 0
                pcbs = defaultdict(list)
        if pcbs:
            yield(pcbs)

    @abstractmethod
    def path_resolution(self, path_request):
        """
        Handles all types of path request.
        """
        raise NotImplementedError

    def _handle_waiting_targets(self, pcb):
        """
        Handle any queries that are waiting for a path to any core AS in an ISD.
        """
        dst_ia = pcb.get_first_pcbm().isd_as
        if not self._is_core_as(dst_ia):
            logging.warning("Invalid waiting target, not a core AS: %s", dst_ia)
            return
        self._send_waiting_queries(dst_ia[0], pcb)

    def _send_waiting_queries(self, dst_isd, pcb):
        targets = self.waiting_targets[dst_isd]
        if not targets:
            return
        path = pcb.get_path(reverse_direction=True)
        src_ia = pcb.get_first_pcbm().isd_as
        while targets:
            seg_req = targets.pop(0)
            req_pkt = self._build_packet(
                PT.PATH_MGMT, dst_ia=src_ia, path=path, payload=seg_req)
            self._send_to_next_hop(req_pkt, path.get_fwd_if())
            logging.info("Waiting request (%s) sent via %s",
                         seg_req.short_desc(), pcb.short_desc())

    def _share_via_zk(self):
        if not self._segs_to_zk:
            return
        logging.info("Sharing %d segment(s) via ZK", len(self._segs_to_zk))
        for pcb_dict in self._gen_prop_recs(self._segs_to_zk,
                                            limit=self.ZK_SHARE_LIMIT):
            data = []
            for type_, pcbs in pcb_dict.items():
                for pcb in pcbs:
                    data.append(bytes([type_]))
                    data.append(pcb.pack())
            self._zk_write(b"".join(data))

    def _zk_write(self, data):
        hash_ = SHA256.new(data).hexdigest()
        try:
            self.path_cache.store("%s-%s" % (hash_, SCIONTime.get_time()), data)
        except ZkNoConnection:
            logging.warning("Unable to store segment(s) in shared path: "
                            "no connection to ZK")

    def run(self):
        """
        Run an instance of the Path Server.
        """
        threading.Thread(
            target=thread_safety_net, args=(self.worker,),
            name="PS.worker", daemon=True).start()
        super().run()
