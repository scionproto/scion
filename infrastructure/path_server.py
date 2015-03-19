"""
path_server.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from _collections import defaultdict
from infrastructure.scion_elem import SCIONElement
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.path_mgmt import (PathSegmentRecords, PathSegmentInfo,
    PathSegmentType as PST, PathMgmtPacket, PathMgmtType as PMT,
    PathSegmentLeases)
from lib.path_db import PathSegmentDB, DBResult
from lib.util import update_dict, init_logging
import copy
import datetime
import logging
import sys
import time


class PathServer(SCIONElement):
    """
    The SCION Path Server.
    """
    def __init__(self, addr, topo_file, config_file):
        SCIONElement.__init__(self, addr, topo_file, config_file=config_file)
        # TODO replace by pathstore instance
        self.down_segments = PathSegmentDB()
        self.core_segments = PathSegmentDB()
        self.pending_down = {}  # Dict of pending DOWN _and_ UP_DOWN requests.
        self.pending_core = {}
        self.waiting_targets = set()  # Used when local PS doesn't have up-path.
        # TODO replace by some cache data struct. (expiringdict ?)

    def _handle_up_segment_record(self, records):
        """
        Handles Up Path registration from local BS.
        """
        pass

    def _handle_down_segment_record(self, records):
        """
        Handles registration of a down path.
        """
        pass

    def _handle_core_segment_record(self, records):
        """
        Handles a core_path record.
        """
        pass

    def send_path_segments(self, path_request, paths):
        """
        Sends path-segments to requester (depending on Path Server's location)
        """
        dst = path_request.hdr.src_addr
        path_request.hdr.path.reverse()
        path_request = PathMgmtPacket(path_request.pack())  # PSz: this is
        # a hack, as path_request with <up-path> only reverses to <down-path>
        # only, and then reversed packet fails with .get_current_iof()
        # FIXME: change .reverse() when only one path segment exists
        path = path_request.hdr.path
        records = PathSegmentRecords.from_values(path_request.payload,
                                                 paths)
        path_reply = PathMgmtPacket.from_values(PMT.RECORDS, records,
                                                path, dst_addr=dst)
        # if path_request.hdr.is_on_up_path():
        #     path_reply.hdr.set_downpath()
        (next_hop, port) = self.get_first_hop(path_reply)
        logging.info("Sending PATH_REC, using path: %s", path)
        self.send(path_reply, next_hop, port)

    def dispatch_path_segment_record(self, pkt):
        """
        Dispatches path record packet.
        """
        assert isinstance(pkt.payload, PathSegmentRecords)
        if pkt.payload.info.type == PST.UP:
            self._handle_up_segment_record(pkt)
        elif pkt.payload.info.type == PST.DOWN:
            self._handle_down_segment_record(pkt)
        elif pkt.payload.info.type == PST.CORE:
            self._handle_core_segment_record(pkt)
        else:
            logging.error("Wrong path record.")

    def handle_path_request(self, path_request):
        """
        Handles all types of path request.
        """
        pass

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        pkt = PathMgmtPacket(packet)

        if pkt.type == PMT.REQUEST:
            self.handle_path_request(pkt)
        elif pkt.type == PMT.RECORDS:
            self.dispatch_path_segment_record(pkt)
        else:
            logging.warning("Type %d not supported.", pkt.type)


class CorePathServer(PathServer):
    """
    SCION Path Server in a core AD. Stores intra ISD down-paths as well as core
    paths and forwards inter-ISD path requests to the corresponding path server.
    """

    class LeasesDict(object):
        """
        Data structure to store leases from other path servers. Keys are segment
        IDs from path-segments.
        """

        class Entry(object):
            """
            Entry for a LeasesDict.
            """
            def __init__(self, isd_id, ad_id, exp_time):
                self.isd_id = isd_id
                self.ad_id = ad_id
                self.exp_time = exp_time

            def __hash__(self):
                return (self.isd_id << 16) | self.ad_id

            def __eq__(self, other):
                if type(other) is type(self):
                    return (self.isd_id == other.isd_id and
                            self.ad_id == other.ad_id)
                else:
                    return False

        def __init__(self, max_capacity=10000):
            self._leases = defaultdict(set)
            self._max_capacity = max_capacity
            self._nentries = 0

        def add_lease(self, segment_id, leaser_isd, leaser_ad, expiration):
            """
            Adds a lease to the cache.

            :param segment_id: the segment's ID
            :type bytes
            :param leaser_isd, leaser_ad: isd/ad of the leaser
            :type int
            :param expiration: expiration time of the lease
            :type int
            """
            if self._nentries >= self._max_capacity:
                self._purge_entries()

            if self._nentries >= self._max_capacity:
                logging.warning("Leases dictionary reached full capacity.")
                return

            entry = self.Entry(leaser_isd, leaser_ad, expiration)
            if entry not in self._leases[segment_id]:
                self._nentries += 1
            else:
                self._leases[segment_id].remove(entry)

            self._leases[segment_id].add(entry)

        def __getitem__(self, segment_id):
            now = time.time()
            if segment_id not in self._leases:
                return []
            else:
                return [(e.isd_id, e.ad_id) for e in self._leases[segment_id]
                        if e.exp_time > now]

        def _purge_entries(self):
            """
            Removes expired leases.
            """
            now = int(time.time())
            for entries in self._leases.items():
                self._nentries -= len(entries)
                entries[:] = [e for e in entries if e.exp_time > now]
                self._nentries += len(entries)

    def __init__(self, addr, topo_file, config_file):
        PathServer.__init__(self, addr, topo_file, config_file)
        # Sanity check that we should indeed be a core path server.
        assert self.topology.is_core_ad, "This shouldn't be a core PS!"

        self.leases = self.LeasesDict()
        self.iftoken2seg = defaultdict(set)

    def _add_if_mappings(self, pcb):
        """
        Adds interface to segment ID mappings.
        """
        for ad in pcb.ads:
            self.iftoken2seg[ad.pcbm.ig_rev_token].add(pcb.segment_id)
            self.iftoken2seg[ad.pcbm.eg_rev_token].add(pcb.segment_id)
            for pm in ad.pms:
                self.iftoken2seg[pm.ig_rev_token].add(pcb.segment_id)
                self.iftoken2seg[pm.eg_rev_token].add(pcb.segment_id)

    def _handle_up_segment_record(self, pkt):
        PathServer._handle_up_segment_record(self, pkt)
        logging.error("Core Path Server received up-path record!")

    def _handle_down_segment_record(self, pkt):
        """
        Handles registration of a down path.
        """
        records = pkt.payload
        if not records.pcbs:
            return
        paths_to_propagate = []
        for pcb in records.pcbs:
            src_isd = pcb.get_first_pcbm().spcbf.isd_id
            src_ad = pcb.get_first_pcbm().ad_id
            dst_ad = pcb.get_last_pcbm().ad_id
            dst_isd = pcb.get_last_pcbm().spcbf.isd_id
            res = self.down_segments.update(pcb, src_isd, src_ad,
                                            dst_isd, dst_ad)
            if res != DBResult.NONE:
                paths_to_propagate.append(pcb)
                logging.info("Down-Segment registered (%d, %d) -> (%d, %d)",
                             src_isd, src_ad, dst_isd, dst_ad)
                if res == DBResult.ENTRY_ADDED:
                    self._add_if_mappings(pcb)
            else:
                logging.info("Down-Segment to (%d, %d) already known.",
                             dst_isd, dst_ad)
        # For now we let every CPS know about all the down-paths within an ISD.
        if paths_to_propagate:
            self._propagate_down_path_segments(paths_to_propagate, records.info)
        # Serve pending requests.
        target = (dst_isd, dst_ad)
        if target in self.pending_down:
            segments_to_send = []
            for path_request in self.pending_down[target]:
                segments_to_send.extend(self.down_segments(dst_isd=dst_isd,
                                                           dst_ad=dst_ad))
                self.send_path_segments(path_request, segments_to_send)
            del self.pending_down[target]

    def _handle_core_segment_record(self, pkt):
        """
        Handles registration of a core path.
        """
        records = pkt.payload
        if not records.pcbs:
            return
        for pcb in records.pcbs:
            src_ad = pcb.get_first_pcbm().ad_id
            src_isd = pcb.get_first_pcbm().spcbf.isd_id
            dst_ad = pcb.get_last_pcbm().ad_id
            dst_isd = pcb.get_last_pcbm().spcbf.isd_id
            res = self.core_segments.update(pcb, src_isd=src_isd, src_ad=src_ad,
                                            dst_isd=dst_isd, dst_ad=dst_ad)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
#             logging.info("Core-Path registered: (%d, %d) -> (%d, %d)",
#                          src_isd, src_ad, dst_isd, dst_ad)
        # Send pending requests that couldn't be processed due to the lack of
        # a core path to the destination PS.
        if self.waiting_targets:
            pcb = records.pcbs[0]
            next_hop = self.ifid2addr[pcb.get_first_pcbm().hof.egress_if]
            path = pcb.get_path()
            targets = copy.deepcopy(self.waiting_targets)
            for (target_isd, target_ad, info) in targets:
                if target_isd == dst_isd and target_ad == dst_ad:
                    path_request = PathMgmtPacket.from_values(PMT.REQUEST, info,
                                                              path, self.addr)
                    self.send(path_request, next_hop)
                    self.waiting_targets.remove((target_isd, target_ad, info))
                    logging.debug("Sending path request %s on newly learned "
                                  "path to (%d, %d)", info, dst_isd, dst_ad)
        # Serve pending core path requests.
        target = ((src_isd, src_ad), (dst_isd, dst_ad))
        if target in self.pending_core:
            segments_to_send = []
            for path_request in self.pending_core[target]:
                segments_to_send.extend(self.core_segments(src_isd=src_isd,
                                                           src_ad=src_ad,
                                                           dst_isd=dst_isd,
                                                           dst_ad=dst_ad))
                self.send_path_segments(path_request, segments_to_send)
            del self.pending_core[target]

    def _propagate_down_path_segments(self, path_segments, path_info):
        """
        Propagate down-path segments to other CPSes in the same ISD.
        """
        # FIXME: For new we broadcast the path to every CPS in the core, even
        # the one we just received it from. Can we avoid that?
        for router in self.topology.routing_edge_routers:
            if router.interface.neighbor_isd == self.topology.isd_id:
                cpaths = self.core_segments(src_isd=self.topology.isd_id,
                    src_ad=self.topology.ad_id,
                    dst_isd=router.interface.neighbor_isd,
                    dst_ad=router.interface.neighbor_ad)
                if cpaths:
                    cpath = cpaths[0].get_path()
                    records = PathSegmentRecords.from_values(path_info,
                                                             path_segments)
                    pkt = PathMgmtPacket.from_values(PMT.RECORDS, records,
                                                     cpath)
                    pkt.hdr.set_downpath()
                    if_id = cpath.get_first_hop_of().egress_if
                    next_hop = self.ifid2addr[if_id]
                    logging.info("Sending down-segment to CPS in (%d, %d).",
                                 router.interface.neighbor_isd,
                                 router.interface.neighbor_ad)
                    self.send(pkt, next_hop)

    def _handle_leases(self, pkt):
        """
        Register an incoming lease for a path segment.
        """
        assert isinstance(pkt.payload, PathSegmentLeases)
        for (isd, ad, exp, seg_id) in pkt.payload.leases:
            self.leases.add_lease(seg_id, isd, ad, exp)
            logging.debug("Added lease from (%d, %d) for %s", isd, ad, seg_id)

    def handle_path_request(self, pkt):
        segment_info = pkt.payload
        dst_isd = segment_info.dst_isd
        dst_ad = segment_info.dst_ad
        ptype = segment_info.type
        logging.info("PATH_REQ received: type: %d, addr: %d,%d", ptype, dst_isd,
                     dst_ad)
        segments_to_send = []
        if ptype == PST.UP:
            logging.warning("CPS received up-segment request! This should not "
                            "happen")
            return
        elif ptype == PST.DOWN:
            paths = self.down_segments(dst_isd=dst_isd,
                                       dst_ad=dst_ad)
            if paths:
                segments_to_send.extend(paths)
            elif dst_isd == self.topology.isd_id:
                update_dict(self.pending_down,
                            (dst_isd, dst_ad),
                            [pkt])
                logging.info("No down-path segment for (%d, %d), "
                             "request is pending.", dst_isd, dst_ad)
                # TODO Sam: Here we should ask other CPSes in the same ISD for
                # the down-path. We first need to decide how to replicate
                # CPS state.
            else:
                # Destination is in a different ISD. Ask a CPS in a this ISD for
                # a down-path using the first available core path.
                update_dict(self.pending_down,
                            (dst_isd, dst_ad),
                            [pkt])
                cpaths = self.core_segments(src_isd=self.topology.isd_id,
                                            src_ad=self.topology.ad_id,
                                            dst_isd=dst_isd)
                if cpaths:
                    path = cpaths[0].get_path()
                    if_id = path.get_first_hop_of().egress_if
                    next_hop = self.ifid2addr[if_id]
                    request = PathMgmtPacket.from_values(PMT.REQUEST,
                                                         segment_info,
                                                         path, self.addr)
                    request.hdr.set_downpath()
                    self.send(request, next_hop)
                    logging.info("Down-Segment request for different ISD. "
                                 "Forwarding request to CPS in (%d, %d).",
                                 cpaths[0].get_last_pcbm().spcbf.isd_id,
                                 cpaths[0].get_last_pcbm().ad_id)
                # If no core_path was available, add request to waiting targets.
                else:
                    self.waiting_targets.add((dst_isd, dst_ad, segment_info))
        elif ptype == PST.CORE:
            src_isd = segment_info.src_isd
            src_ad = segment_info.src_ad
            key = ((src_isd, src_ad), (dst_isd, dst_ad))
            paths = self.core_segments(src_isd=src_isd, src_ad=src_ad,
                                       dst_isd=dst_isd, dst_ad=dst_ad)
            if paths:
                segments_to_send.extend(paths)
            else:
                update_dict(self.pending_core, key, [pkt])
                logging.info("No core-segment for (%d, %d) -> (%d, %d), "
                             "request is pending.", src_isd, src_ad,
                             dst_isd, dst_ad)
        else:
            logging.error("CPS received unsupported path request!.")
        if segments_to_send:
            self.send_path_segments(pkt, segments_to_send)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        pkt = PathMgmtPacket(packet)

        if pkt.type == PMT.REQUEST:
            self.handle_path_request(pkt)
        elif pkt.type == PMT.RECORDS:
            self.dispatch_path_segment_record(pkt)
        elif pkt.type == PMT.LEASES:
            self._handle_leases(pkt)
        else:
            logging.warning("Type %d not supported.", pkt.type)


class LocalPathServer(PathServer):
    """
    SCION Path Server in a non-core AD. Stores up-paths to the core and
    registers down-paths with the CPS. Can cache paths learned from a CPS.
    """
    def __init__(self, addr, topo_file, config_file):
        PathServer.__init__(self, addr, topo_file, config_file)
        # Sanity check that we should indeed be a local path server.
        assert not self.topology.is_core_ad, "This shouldn't be a local PS!"
        # Database of up-segments to the core.
        self.up_segments = PathSegmentDB()
        self.pending_up = []  # List of pending UP requests.

    def _send_leases(self, orig_pkt, leases):
        """
        Sends leases to a CPS.
        """
        dst = orig_pkt.hdr.src_addr
        orig_pkt.hdr.path.reverse()
        orig_pkt = PathMgmtPacket(orig_pkt.pack())  # PSz: this is
        # a hack, as path_request with <up-path> only reverses to <down-path>
        # only, and then reversed packet fails with .get_current_iof()
        # FIXME: change .reverse() when only one path segment exists
        path = orig_pkt.hdr.path
        payload = PathSegmentLeases.from_values(len(leases), leases)
        leases_pkt = PathMgmtPacket.from_values(PMT.LEASES, payload, path,
                                                dst_addr=dst)

        (dst, dst_port) = self.get_first_hop(leases_pkt)
        logging.debug("Sending leases to CPS.")
        self.send(leases_pkt, dst, dst_port)

    def _handle_up_segment_record(self, pkt):
        """
        Handles Up Path registration from local BS.
        """
        records = pkt.payload
        if not records.pcbs:
            return
        for pcb in records.pcbs:
            self.up_segments.update(pcb, self.topology.isd_id,
                                    self.topology.ad_id,
                                    pcb.get_first_pcbm().spcbf.isd_id,
                                    pcb.get_first_pcbm().ad_id)
            logging.info("Up-Segment to (%d, %d) registered.",
                         pcb.get_first_pcbm().spcbf.isd_id,
                         pcb.get_first_pcbm().ad_id)
        # Sending pending targets to the core using first registered up-path.
        if self.waiting_targets:
            pcb = records.pcbs[0]
            path = pcb.get_path(reverse_direction=True)
            if_id = path.get_first_hop_of().ingress_if
            next_hop = self.ifid2addr[if_id]
            targets = copy.copy(self.waiting_targets)
            for (isd, ad, info) in targets:
                path_request = PathMgmtPacket.from_values(PMT.REQUEST, info,
                                                          path, self.addr)
                self.send(path_request, next_hop)
                logging.info("PATH_REQ sent using (first) registered up-path")
                self.waiting_targets.remove((isd, ad, info))
        # Handling pending UP_PATH requests.
        for path_request in self.pending_up:
            self.send_path_segments(path_request, self.up_segments())
        self.pending_up = []

    def _handle_down_segment_record(self, pkt):
        records = pkt.payload
        if not records.pcbs:
            return
        leases = []
        for pcb in records.pcbs:
            src_isd = pcb.get_first_pcbm().spcbf.isd_id
            src_ad = pcb.get_first_pcbm().ad_id
            dst_ad = pcb.get_last_pcbm().ad_id
            dst_isd = pcb.get_last_pcbm().spcbf.isd_id
            self.down_segments.update(pcb, src_isd, src_ad, dst_isd, dst_ad)
            # TODO: For now we immediately notify the CPS about the caching of
            # the path-segment. In the future we should only do that when we
            # add the segment to the longer-term cache.
            leases.append((self.topology.isd_id, self.topology.ad_id,
                           pcb.get_expiration_time(), pcb.segment_id))
            logging.info("Down-Segment registered (%d, %d) -> (%d, %d)",
                         src_isd, src_ad, dst_isd, dst_ad)
        # Send leases to CPS
        if leases:
            self._send_leases(pkt, leases)
        # serve pending requests
        target = (dst_isd, dst_ad)
        if target in self.pending_down:
            segments_to_send = []
            for path_request in self.pending_down[target]:
                segments_to_send.extend(self.down_segments(dst_isd=dst_isd,
                                                           dst_ad=dst_ad))
                self.send_path_segments(path_request, segments_to_send)
            del self.pending_down[target]

    def _handle_core_segment_record(self, pkt):
        """
        Handles registration of a core path.
        """
        records = pkt.payload
        if not records.pcbs:
            return
        leases = []
        for pcb in records.pcbs:
            src_ad = pcb.get_first_pcbm().ad_id
            src_isd = pcb.get_first_pcbm().spcbf.isd_id
            dst_ad = pcb.get_last_pcbm().ad_id
            dst_isd = pcb.get_last_pcbm().spcbf.isd_id
            self.core_segments.update(pcb, src_isd=src_isd, src_ad=src_ad,
                                      dst_isd=dst_isd, dst_ad=dst_ad)
            leases.append((self.topology.isd_id, self.topology.ad_id,
                           pcb.get_expiration_time(), pcb.segment_id))
            logging.info("Core-Segment registered: (%d, %d) -> (%d, %d)",
                         src_isd, src_ad, dst_isd, dst_ad)

        # Send leases to CPS
        if leases:
            self._send_leases(pkt, leases)
        # Serve pending core path requests.
        target = ((src_isd, src_ad), (dst_isd, dst_ad))
        if target in self.pending_core:
            segments_to_send = []
            for path_request in self.pending_core[target]:
                segments_to_send.extend(self.core_segments(src_isd=src_isd,
                                                           src_ad=src_ad,
                                                           dst_isd=dst_isd,
                                                           dst_ad=dst_ad))
                self.send_path_segments(path_request, segments_to_send)
            del self.pending_core[target]

    def _request_paths_from_core(self, ptype, dst_isd, dst_ad,
                                 src_isd=None, src_ad=None):
        """
        Tries to request core PS for given target (isd, ad).
        """
        assert ptype in [PST.DOWN, PST.CORE]
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id
        info = PathSegmentInfo.from_values(ptype, src_isd, dst_isd,
                                           src_ad, dst_ad)
        if not len(self.up_segments):
            logging.info('Pending target added')
            self.waiting_targets.add((dst_isd, dst_ad, info))
        else:
            logging.info('Requesting path from core: type: %d, addr: %d,%d',
                         ptype, dst_isd, dst_ad)
            pcb = self.up_segments()[0]
            path = pcb.get_path(reverse_direction=True)
            path.up_segment_info.up_flag = True  # FIXME: temporary hack. A very
            # first path is _always_ down-path, any subsequent is up-path.
            if_id = path.get_first_hop_of().ingress_if
            next_hop = self.ifid2addr[if_id]
            path_request = PathMgmtPacket.from_values(PMT.REQUEST, info,
                                                      path, self.addr)
            self.send(path_request, next_hop)

    def handle_path_request(self, pkt):
        """
        Handles all types of path request.
        """
        segment_info = pkt.payload
        dst_isd = segment_info.dst_isd
        dst_ad = segment_info.dst_ad
        ptype = segment_info.type
        logging.info("PATH_REQ received: type: %d, addr: %d,%d", ptype, dst_isd,
                     dst_ad)
        paths_to_send = []
        # Requester wants up-path.
        if ptype in [PST.UP, PST.UP_DOWN]:
            if len(self.up_segments):
                paths_to_send.extend(self.up_segments())
            else:
                if type == PST.UP_DOWN:
                    update_dict(self.pending_down,
                                (dst_isd, dst_ad),
                                [pkt])
                    self.waiting_targets.add((dst_isd, dst_ad))
                else:  # PST.UP
                    self.pending_up.append(pkt)
                return
        # Requester wants down-path.
        if (ptype in [PST.DOWN, PST.UP_DOWN]):
            paths = self.down_segments(dst_isd=dst_isd, dst_ad=dst_ad)
            if paths:
                paths_to_send.extend(paths)
            else:
                update_dict(self.pending_down,
                            (dst_isd, dst_ad),
                            [pkt])
                self._request_paths_from_core(PST.DOWN, dst_isd, dst_ad)
                logging.info("No downpath, request is pending.")
        # Requester wants core-path.
        if ptype == PST.CORE:
            src_isd = segment_info.src_isd
            src_ad = segment_info.src_ad
            paths = self.core_segments(src_isd=src_isd, src_ad=src_ad,
                                       dst_isd=dst_isd, dst_ad=dst_ad)
            if paths:
                paths_to_send.extend(paths)
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
    init_logging()
    if len(sys.argv) != 5:
        logging.error("run: %s <core|local>  IP topo_file conf_file",
                      sys.argv[0])
        sys.exit()

    if sys.argv[1] == "core":
        path_server = CorePathServer(IPv4HostAddr(sys.argv[2]), sys.argv[3],
                                     sys.argv[4])
    elif sys.argv[1] == "local":
        path_server = LocalPathServer(IPv4HostAddr(sys.argv[2]), sys.argv[3],
                                      sys.argv[4])
    else:
        logging.error("First parameter can only be 'local' or 'core'!")
        sys.exit()

    logging.info("Started: %s", datetime.datetime.now())
    path_server.run()

if __name__ == "__main__":
    main()
