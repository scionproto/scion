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
import argparse
import copy
import datetime
import logging
import threading
import sys
from _collections import defaultdict
from abc import ABCMeta, abstractmethod

# External packages
from Crypto.Hash import SHA256
from external.expiring_dict import ExpiringDict

# SCION
from infrastructure.scion_elem import SCIONElement
from lib.crypto.hash_chain import HashChain
from lib.defines import PATH_SERVICE, SCION_UDP_PORT
from lib.log import init_logging, log_exception
from lib.packet.path import UP_IOF
from lib.packet.path_mgmt import (
    PathMgmtPacket,
    PathMgmtType as PMT,
    PathSegmentInfo,
    PathSegmentRecords,
    PathSegmentType as PST,
    RevocationInfo,
)
from lib.packet.scion_addr import ISD_AD
from lib.path_db import DBResult, PathSegmentDB
from lib.thread import thread_safety_net
from lib.util import (
    SCIONTime,
    handle_signals,
    sleep_interval,
    trace,
    update_dict,
)
from lib.zookeeper import ZkNoConnection, ZkSharedCache, Zookeeper


class PathServer(SCIONElement, metaclass=ABCMeta):
    """
    The SCION Path Server.
    """
    MAX_SEG_NO = 5  # TODO: replace by config variable.
    # ZK path for incoming PATHs
    ZK_PATH_CACHE_PATH = "path_cache"

    def __init__(self, server_id, topo_file, config_file, is_sim=False):
        """
        Initialize an instance of the class PathServer.

        :param server_id:
        :type server_id:
        :param topo_file:
        :type topo_file:
        :param config_file:
        :type config_file:
        :param is_sim: running in simulator
        :type is_sim: bool
        """
        super().__init__(PATH_SERVICE, topo_file, server_id=server_id,
                         config_file=config_file, is_sim=is_sim)
        # TODO replace by pathstore instance
        self.down_segments = PathSegmentDB()
        self.core_segments = PathSegmentDB()  # Direction of the propagation.
        self.pending_down = {}  # Dict of pending DOWN _and_ UP_DOWN requests.
        self.pending_core = {}
        self.waiting_targets = set()  # Used when local PS doesn't have up-path.
        self.revocations = ExpiringDict(1000, 300)
        self.iftoken2seg = defaultdict(set)

        if not is_sim:
            # Add more IPs here if we support dual-stack
            name_addrs = "\0".join([self.id, str(SCION_UDP_PORT),
                                    str(self.addr.host_addr)])
            self.zk = Zookeeper(
                self.topology.isd_id, self.topology.ad_id, PATH_SERVICE,
                name_addrs, self.topology.zookeepers)
            self.zk.retry("Joining party", self.zk.party_setup)
            self.path_cache = ZkSharedCache(self.zk, self.ZK_PATH_CACHE_PATH,
                                            self._cached_entries_handler,
                                            self.config.propagation_time)

    @abstractmethod
    def worker(self):
        """
        Worker thread that takes care of reading shared paths from ZK, and
        handling master election for core servers.
        """
        raise NotImplementedError

    @abstractmethod
    def _cached_entries_handler(self, raw_entries):
        """
        Handles cached through ZK entries, passed as a list.
        """
        raise NotImplementedError

    def _add_if_mappings(self, pcb):
        """
        Add if revocation token to segment ID mappings.
        """
        for ad in pcb.ads:
            self.iftoken2seg[ad.pcbm.ig_rev_token].add(pcb.segment_id)
            self.iftoken2seg[ad.eg_rev_token].add(pcb.segment_id)
            for pm in ad.pms:
                self.iftoken2seg[pm.ig_rev_token].add(pcb.segment_id)

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

    def _verify_revocation(self, rev_info):
        """
        Verifies the revocation token.
        """
        return HashChain.verify(rev_info.proof, rev_info.rev_token)

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
            logging.debug("Received revocation from %s:\n%s", pkt.hdr.src_addr,
                          rev_info)
        # Verify revocation.
        if not self._verify_revocation(rev_info):
            logging.info("Revocation verification failed.")
            return
        # Remove segments that contain the revoked interface.
        self._remove_revoked_segments(rev_info)

    def _remove_revoked_segments(self, rev_info):
        """
        Remove segments that contain a revoked interface.

        :param rev_info: The revocation info
        :type rev_info: RevocationInfo
        """
        segments = self.iftoken2seg[rev_info.rev_token]
        while segments:
            sid = segments.pop()
            # Delete segment from DB.
            self.down_segments.delete(sid)
            self.core_segments.delete(sid)
        del self.iftoken2seg[rev_info.rev_token]

    def send_path_segments(self, path_request, paths):
        """
        Sends path-segments to requester (depending on Path Server's location)
        """
        dst = path_request.hdr.src_addr
        path = path_request.hdr.get_path()
        path.reverse()
        records = PathSegmentRecords.from_values(path_request.get_payload(),
                                                 paths)
        path_reply = PathMgmtPacket.from_values(PMT.RECORDS, records, path,
                                                self.addr.get_isd_ad(), dst)
        (next_hop, port) = self.get_first_hop(path_reply)
        logging.info("Sending PATH_REC, using path: %s", path)
        self.send(path_reply, next_hop, port)

    def dispatch_path_segment_record(self, pkt):
        """
        Dispatches path record packet.
        """
        payload = pkt.get_payload()
        assert isinstance(payload, PathSegmentRecords)
        if payload.info.type == PST.UP:
            self._handle_up_segment_record(pkt)
        elif payload.info.type in [PST.DOWN, PST.UP_DOWN]:
            self._handle_down_segment_record(pkt)
        elif payload.info.type == PST.CORE:
            self._handle_core_segment_record(pkt)
        else:
            logging.error("Wrong path record.")

    @abstractmethod
    def handle_path_request(self, path_request):
        """
        Handles all types of path request.
        """
        raise NotImplementedError

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        pkt = PathMgmtPacket(packet)

        if pkt.type == PMT.REQUEST:
            self.handle_path_request(pkt)
        elif pkt.type == PMT.RECORDS:
            self.dispatch_path_segment_record(pkt)
        elif pkt.type == PMT.REVOCATION:
            self._handle_revocation(pkt)
        else:
            logging.warning("Type %d not supported.", pkt.type)

    def _share_segments(self, pkt):
        """
        Share path segments (via ZK) with other path servers.
        """
        pkt_packed = pkt.pack()
        pkt_hash = SHA256.new(pkt_packed).hexdigest()
        try:
            self.path_cache.store(pkt_hash, pkt_packed)
            logging.debug("Segment stored in ZK: %s...", pkt_hash[:5])
        except ZkNoConnection:
            logging.warning("Unable to store segment in shared path: "
                            "no connection to ZK")

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
    def __init__(self, server_id, topo_file, config_file, is_sim=False):
        """
        Initialize an instance of the class CorePathServer.

        :param server_id:
        :type server_id:
        :param topo_file:
        :type topo_file:
        :param config_file:
        :type config_file:
        :param is_sim: running in simulator
        :type is_sim: bool
        """
        super().__init__(server_id, topo_file, config_file, is_sim=is_sim)
        # Sanity check that we should indeed be a core path server.
        assert self.topology.is_core_ad, "This shouldn't be a core PS!"
        self.core_ads = set()  # Set of core ADs only from local ISD.
        self._master_id = None  # Address of master core Path Server.

    def worker(self):
        """
        Worker thread that takes care of reading shared paths from ZK, and
        handling master election.
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
                    # TODO(PSz): clean old zk entries
                    pass
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')
                pass
            self._update_master()

    def _cached_entries_handler(self, raw_entries):
        for entry in raw_entries:
            self._handle_core_segment_record(PathMgmtPacket(raw=entry), True)

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
        # TODO(PSz): send all local down- and (?) core-paths to the new master,
        # consider some easy mechanisms for avoiding registration storm.
        # check whether master exists
        if not self._master_id or self._is_master():
            logging.warning('Sync abandoned: master not set or I am a master')
            return
        logging.debug("TODO: Syncing with %s", self._master_id)
        pass

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
        if not records.pcbs:
            return
        paths_to_propagate = []
        for pcb in records.pcbs:
            assert pcb.segment_id != 32 * b"\x00", \
                "Trying to register a segment with ID 0:\n%s" % pcb
            src_isd = pcb.get_first_pcbm().isd_id
            src_ad = pcb.get_first_pcbm().ad_id
            dst_ad = pcb.get_last_pcbm().ad_id
            dst_isd = pcb.get_last_pcbm().isd_id
            res = self.down_segments.update(pcb, src_isd, src_ad,
                                            dst_isd, dst_ad)
            if (dst_isd == pkt.hdr.src_addr.isd_id and
                    dst_ad == pkt.hdr.src_addr.ad_id):
                # Only propagate this path if it was registered with us by the
                # down-stream AD.
                paths_to_propagate.append(pcb)
            if res != DBResult.NONE:
                logging.info("Down-Segment registered (%d, %d) -> (%d, %d)",
                             src_isd, src_ad, dst_isd, dst_ad)
                if res == DBResult.ENTRY_ADDED:
                    self._add_if_mappings(pcb)
            else:
                logging.info("Down-Segment to (%d, %d) already known.",
                             dst_isd, dst_ad)
        # For now we let every CPS know about all the down-paths within an ISD.
        # Also send paths to local master.
        # FIXME: putting all paths into single packet may be not a good decision
        if paths_to_propagate:
            records = PathSegmentRecords.from_values(records.info,
                                                     paths_to_propagate)
            pkt = PathMgmtPacket.from_values(PMT.RECORDS, records, None,
                                             self.addr, ISD_AD(0, 0))
            # Send paths to local master.
            if self._master_id and not self._is_master():
                self._send_to_master(pkt)
            # Now propagate paths to other core ADs (in the ISD).
            logging.debug("Propagate among core ADs")
            self._propagate_to_core_ads(pkt)
        # Serve pending requests.
        target = (dst_isd, dst_ad)
        if target in self.pending_down:
            segments_to_send = self.down_segments(last_isd=dst_isd,
                                                  last_ad=dst_ad)
            segments_to_send = segments_to_send[:self.MAX_SEG_NO]
            for path_request in self.pending_down[target]:
                self.send_path_segments(path_request, segments_to_send)
            del self.pending_down[target]

    def _handle_core_segment_record(self, pkt, from_zk=False):
        """
        Handle registration of a core path.
        """
        records = pkt.get_payload()
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
                logging.info("Core-Path registered: (%d, %d) -> (%d, %d), "
                             "from_zk: %s", src_isd, src_ad, dst_isd, dst_ad,
                             from_zk)
            if dst_isd == self.topology.isd_id:
                self.core_ads.add((dst_isd, dst_ad))
            else:
                pcb_from_local_isd = False
        if not from_zk:
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
            next_hop = self.ifid2addr[pcb.get_last_pcbm().hof.ingress_if]
            path = pcb.get_path(reverse_direction=True)
            targets = copy.deepcopy(self.waiting_targets)
            for (target_isd, target_ad, info) in targets:
                if target_isd == dst_isd:
                    dst_isd_ad = ISD_AD(dst_isd, dst_ad)
                    path_request = PathMgmtPacket.from_values(PMT.REQUEST, info,
                                                              path, self.addr,
                                                              dst_isd_ad)
                    self.send(path_request, next_hop)
                    self.waiting_targets.remove((target_isd, target_ad, info))
                    logging.debug("Sending path request %s on newly learned "
                                  "path to (%d, %d)", info, dst_isd, dst_ad)
        # Serve pending core path requests.
        for target in [((src_isd, src_ad), (dst_isd, dst_ad)),
                       ((src_isd, src_ad), (dst_isd, 0))]:
            if self.pending_core:
                logging.debug("D01 Target: %s, pending_core: %s " % (target,
                              self.pending_core))
            if target in self.pending_core:
                segments_to_send = self.core_segments(first_isd=dst_isd,
                                                      first_ad=dst_ad or None,
                                                      last_isd=src_isd,
                                                      last_ad=src_ad)
                segments_to_send = segments_to_send[:self.MAX_SEG_NO]
                for path_request in self.pending_core[target]:
                    self.send_path_segments(path_request, segments_to_send)
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
        pkt.hdr.dst_addr.isd_id = self.topology.isd_id
        pkt.hdr.dst_addr.ad_id = self.topology.ad_id
        pkt.hdr.src_addr.isd_id = self.topology.isd_id
        pkt.hdr.src_addr.ad_id = self.topology.ad_id
        self.send(pkt, master)
        logging.debug("Packet sent to master %s", master)

    def _query_master(self, ptype, dst_isd, dst_ad, src_isd=None, src_ad=None):
        """
        Query master for a path.
        """
        # TODO(PSz): don't send path back to master.
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id

        info = PathSegmentInfo.from_values(ptype, src_isd, dst_isd,
                                           src_ad, dst_ad)
        path_request = PathMgmtPacket.from_values(PMT.REQUEST, info,
                                                  None, self.addr,
                                                  ISD_AD(src_isd, src_ad))
        logging.debug("Asking master for path: (%d, %d) -> (%d, %d)" %
                      (src_isd, src_ad, dst_isd, dst_ad))
        self._send_to_master(path_request)

    def _propagate_to_core_ads(self, pkt, inter_isd=False):
        """
        Propagate 'pkt' to other core ADs.

        :param pkt: the packet to propagate (without path)
        :type pkt: lib.packet.packet_base.PacketBase
        :param inter_isd: whether the packet should be propagated across ISDs
        :type inter_isd: bool
        """
        # FIXME: For new we broadcast the path to every CPS in the core, even
        # the one we just received it from. Can we avoid that?
        for (isd, ad) in self.core_ads:
            if inter_isd or isd == self.topology.isd_id:
                cpaths = self.core_segments(first_isd=isd, first_ad=ad,
                                            last_isd=self.topology.isd_id,
                                            last_ad=self.topology.ad_id)
                if cpaths:
                    cpath = cpaths[0].get_path(reverse_direction=True)
                    pkt.hdr.set_path(cpath)
                    pkt.hdr.dst_addr.isd_id = isd
                    pkt.hdr.dst_addr.ad_id = ad
                    next_hop = self.ifid2addr[cpath.get_fwd_if()]
                    logging.info("Sending packet to CPS in (%d, %d).", isd, ad)
                    self.send(pkt, next_hop)
                else:
                    logging.warning("Path to AD (%d, %d) not found.", isd, ad)

    def handle_path_request(self, pkt):
        """

        :param pkt:
        :type pkt:
        """
        segment_info = pkt.get_payload()
        dst_isd = segment_info.dst_isd
        dst_ad = segment_info.dst_ad
        ptype = segment_info.type
        logging.info("PATH_REQ received: type: %d, addr: (%d, %d)", ptype,
                     dst_isd, dst_ad)
        segments_to_send = []
        if ptype == PST.UP:
            logging.warning("CPS received up-segment request! This should not "
                            "happen")
            return
        elif ptype in [PST.DOWN, PST.UP_DOWN]:
            paths = self.down_segments(last_isd=dst_isd, last_ad=dst_ad)
            if paths:
                paths = paths[:self.MAX_SEG_NO]
                segments_to_send.extend(paths)
            elif dst_isd == self.topology.isd_id:
                update_dict(self.pending_down, (dst_isd, dst_ad), [pkt])
                logging.info("No down-path segment for (%d, %d), "
                             "request is pending.", dst_isd, dst_ad)
                if not self._is_master():
                    self._query_master(ptype, dst_isd, dst_ad)
            else:
                # Destination is in a different ISD. Ask a CPS in a this ISD for
                # a down-path using the first available core path.
                update_dict(self.pending_down, (dst_isd, dst_ad), [pkt])
                cpaths = self.core_segments(first_isd=dst_isd,
                                            last_isd=self.topology.isd_id,
                                            last_ad=self.topology.ad_id)
                if cpaths:
                    path = cpaths[0].get_path(reverse_direction=True)
                    dst_isd_ad = ISD_AD(cpaths[0].get_first_pcbm().isd_id,
                                        cpaths[0].get_first_pcbm().ad_id)
                    next_hop = self.ifid2addr[path.get_fwd_if()]
                    request = PathMgmtPacket.from_values(PMT.REQUEST,
                                                         segment_info, path,
                                                         self.addr, dst_isd_ad)
                    self.send(request, next_hop)
                    logging.info("Down-Segment request for different ISD. "
                                 "Forwarding request to CPS in (%d, %d).",
                                 dst_isd_ad.isd, dst_isd_ad.ad)
                # If no core_path was available, add request to waiting targets.
                else:
                    self.waiting_targets.add((dst_isd, dst_ad, segment_info))
                    if not self._is_master():
                        # Ask for any path to dst_isd
                        self._query_master(PST.CORE, dst_isd, 0)
        elif ptype == PST.CORE:
            src_isd = segment_info.src_isd
            src_ad = segment_info.src_ad
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
                    self._query_master(ptype, dst_isd, dst_ad, src_isd, src_ad)
        else:
            logging.error("CPS received unsupported path request!.")
        if segments_to_send:
            self.send_path_segments(pkt, segments_to_send)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.

        :param packet:
        :type packet:
        :param sender:
        :type sender:
        :param from_local_socket:
        :type from_local_socket:
        """
        pkt = PathMgmtPacket(packet)

        if pkt.type == PMT.REQUEST:
            self.handle_path_request(pkt)
        elif pkt.type == PMT.RECORDS:
            self.dispatch_path_segment_record(pkt)
        elif pkt.type == PMT.REVOCATION:
            self._handle_revocation(pkt)
        else:
            logging.warning("Type %d not supported.", pkt.type)


class LocalPathServer(PathServer):
    """
    SCION Path Server in a non-core AD. Stores up-paths to the core and
    registers down-paths with the CPS. Can cache paths learned from a CPS.
    """
    def __init__(self, server_id, topo_file, config_file, is_sim=False):
        """
        Initialize an instance of the class LocalPathServer.

        :param server_id:
        :type server_id:
        :param topo_file:
        :type topo_file:
        :param config_file:
        :type config_file:
        :param is_sim: running in simulator
        :type is_sim: bool
        """
        super().__init__(server_id, topo_file, config_file, is_sim=is_sim)
        # Sanity check that we should indeed be a local path server.
        assert not self.topology.is_core_ad, "This shouldn't be a local PS!"
        # Database of up-segments to the core.
        self.up_segments = PathSegmentDB()
        self.pending_up = []  # List of pending UP requests.

    def worker(self):
        """
        Worker thread that takes care of reading shared paths from ZK.
        """
        # PSz: in local PS we may also need master election, as someone needs to
        # clean ZK's cache periodically.
        worker_cycle = 1.0
        start = SCIONTime.get_time()
        while True:
            sleep_interval(start, worker_cycle, "PS.worker cycle")
            start = SCIONTime.get_time()
            # Read cached entries.
            try:
                self.path_cache.process()
            except ZkNoConnection:
                logging.warning('worker(): ZkNoConnection')

    def _cached_entries_handler(self, raw_entries):
        for entry in raw_entries:
            self._handle_up_segment_record(PathMgmtPacket(raw=entry), True)

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
                logging.info("Up-Segment to (%d, %d) registered, from_zk: %s.",
                             pcb.get_first_pcbm().isd_id,
                             pcb.get_first_pcbm().ad_id, from_zk)
        # Share Up Segment via ZK.
        if not from_zk:
            self._share_segments(pkt)
        # Sending pending targets to the core using first registered up-path.
        if self.waiting_targets:
            pcb = records.pcbs[0]
            path = pcb.get_path(reverse_direction=True)
            dst_isd_ad = ISD_AD(pcb.get_isd(), pcb.get_first_pcbm().ad_id)
            next_hop = self.ifid2addr[path.get_fwd_if()]
            targets = copy.copy(self.waiting_targets)
            for (isd, ad, info) in targets:
                path_request = PathMgmtPacket.from_values(PMT.REQUEST, info,
                                                          path, self.addr,
                                                          dst_isd_ad)
                self.send(path_request, next_hop)
                logging.info("PATH_REQ sent using (first) registered up-path")
                self.waiting_targets.remove((isd, ad, info))
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
                logging.info("Core-Segment registered: (%d, %d) -> (%d, %d)",
                             src_isd, src_ad, dst_isd, dst_ad)
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
        Remove segments that contain a revoked interface.

        :param rev_info: The revocation info
        :type rev_info: RevocationInfo
        """
        segments = self.iftoken2seg[rev_info.rev_token]
        while segments:
            sid = segments.pop()
            # Delete segment from DB.
            self.up_segments.delete(sid)
            self.down_segments.delete(sid)
            self.core_segments.delete(sid)
        del self.iftoken2seg[rev_info.rev_token]

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
        info = PathSegmentInfo.from_values(ptype, src_isd, dst_isd,
                                           src_ad, dst_ad)
        if not len(self.up_segments) and ptype == PST.DOWN:
            logging.info('Pending target added (%d, %d)', dst_isd, dst_ad)
            self.waiting_targets.add((dst_isd, dst_ad, info))
        elif len(self.up_segments):
            logging.info('Requesting path from core: type: %d, addr: %d,%d',
                         ptype, dst_isd, dst_ad)
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
            dst_isd_ad = ISD_AD(pcb.get_isd(), pcb.get_first_pcbm().ad_id)
            # FIXME(PSz): temporary hack. A very first path is _always_
            # down-path, any subsequent is up-path.
            # Above comment is from 2015-01-28, f288fb53
            up_seg_info = path.get_ofs_by_label(UP_IOF)[0]
            up_seg_info.up_flag = True
            next_hop = self.ifid2addr[path.get_fwd_if()]
            path_request = PathMgmtPacket.from_values(
                PMT.REQUEST, info, path, self.addr, dst_isd_ad)
            self.send(path_request, next_hop)

    def handle_path_request(self, pkt):
        """
        Handle all types of path request.

        :param pkt:
        :type pkt:
        """
        segment_info = pkt.get_payload()
        dst_isd = segment_info.dst_isd
        dst_ad = segment_info.dst_ad
        ptype = segment_info.type
        logging.info("PATH_REQ received: type: %d, addr: %d,%d", ptype, dst_isd,
                     dst_ad)
        paths_to_send = []
        # Requester wants up-path.
        if ptype in [PST.UP, PST.UP_DOWN]:
            if len(self.up_segments):
                paths_to_send.extend(self.up_segments()[:self.MAX_SEG_NO])
            else:
                if ptype == PST.UP_DOWN:
                    update_dict(self.pending_down, (dst_isd, dst_ad), [pkt])
                    self.waiting_targets.add((dst_isd, dst_ad, segment_info))
                self.pending_up.append(pkt)
                return
        # Requester wants down-path.
        if (ptype in [PST.DOWN, PST.UP_DOWN]):
            paths = self.down_segments(last_isd=dst_isd, last_ad=dst_ad)
            if paths:
                paths_to_send.extend(paths[:self.MAX_SEG_NO])
            else:
                update_dict(self.pending_down, (dst_isd, dst_ad), [pkt])
                self._request_paths_from_core(PST.DOWN, dst_isd, dst_ad)
                logging.info("No downpath, request is pending.")
        # Requester wants core-path.
        if ptype == PST.CORE:
            src_isd = segment_info.src_isd
            src_ad = segment_info.src_ad
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


def main():
    """
    Main function.
    """
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('type', choices=['core', 'local'],
                        help='Core or local path server')
    parser.add_argument('server_id', help='Server identifier')
    parser.add_argument('topo_file', help='Topology file')
    parser.add_argument('conf_file', help='AD configuration file')
    parser.add_argument('log_file', help='Log file')
    args = parser.parse_args()
    init_logging(args.log_file)

    if args.type == "core":
        path_server = CorePathServer(args.server_id, args.topo_file,
                                     args.conf_file)
    elif args.type == "local":
        path_server = LocalPathServer(args.server_id, args.topo_file,
                                      args.conf_file)
    else:
        logging.error("First parameter can only be 'local' or 'core'!")
        sys.exit()

    trace(path_server.id)
    logging.info("Started: %s", datetime.datetime.now())
    path_server.run()

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
