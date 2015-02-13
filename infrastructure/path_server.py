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

import copy
from infrastructure.scion_elem import SCIONElement
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.pcb import (PathSegmentRequest, PathSegmentRecords,
    PathSegmentInfo, PathSegmentType as PST)
from lib.packet.scion import PacketType as PT
from lib.packet.scion import SCIONPacket, get_type
from lib.path_db import PathSegmentDB
from lib.util import update_dict
import logging
import sys


class PathServer(SCIONElement):
    """
    The SCION Path Server.
    """
    def __init__(self, addr, topo_file, config_file):
        SCIONElement.__init__(self, addr, topo_file, config_file)
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
        for pcb in records.pcbs:
            dst_ad = pcb.get_last_ad().ad_id
            dst_isd = pcb.get_last_ad().spcbf.isd_id
            self.down_segments.insert(pcb, self.topology.isd_id,
                                      self.topology.ad_id, dst_isd, dst_ad)
            logging.info("Down-Segment registered (%d, %d)", dst_isd, dst_ad)

        # serve pending requests
        target = (dst_isd, dst_ad)
        if target in self.pending_down:
            segments_to_send = []
            for path_request in self.pending_down[target]:
                segments_to_send.extend(self.down_segments(dst_isd=dst_isd,
                                                           dst_ad=dst_ad))
                self.send_path_segments(path_request, segments_to_send)
            del self.pending_down[target]

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
        path_request = PathSegmentRequest(path_request.pack()) #PSz: this is
        # a hack, as path_request with <up-path> only reverses to <down-path>
        # only, and then reversed packet fails with .get_current_iof()
        # FIXME: change .reverse() when only one path segment exists
        path = path_request.hdr.path
        path_reply = PathSegmentRecords.from_values(dst, path_request.info,
                                             paths, path)
        # if path_request.hdr.is_on_up_path():
        #     path_reply.hdr.set_downpath()
        (next_hop, port) = self.get_first_hop(path_reply)
        logging.info("Sending PATH_REC, using path: %s", path)
        self.send(path_reply, next_hop, port)

    def dispatch_path_segment_record(self, rec):
        """
        Dispatches path record packet.
        """
        assert isinstance(rec, PathSegmentRecords)
        if rec.info.type == PST.UP:
            self._handle_up_segment_record(rec)
        elif rec.info.type == PST.DOWN:
            self._handle_down_segment_record(rec)
        elif rec.info.type == PST.CORE:
            self._handle_core_segment_record(rec)
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
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)

        if ptype == PT.PATH_REQ:
            self.handle_path_request(PathSegmentRequest(packet))
        elif ptype == PT.PATH_REC:
            self.dispatch_path_segment_record(PathSegmentRecords(packet))
        else:
            logging.warning("Type %d not supported.", ptype)


class CorePathServer(PathServer):
    """
    SCION Path Server in a core AD. Stores intra ISD down-paths as well as core
    paths and forwards inter-ISD path requests to the corresponding path server.
    """
    def __init__(self, addr, topo_file, config_file):
        PathServer.__init__(self, addr, topo_file, config_file)
        # Sanity check that we should indeed be a core path server.
        assert self.topology.is_core_ad, "This shouldn't be a core PS!"

    def _handle_up_segment_record(self, records):
        PathServer._handle_up_segment_record(self, records)
        logging.error("Core Path Server received up-path record!")

    def _handle_down_segment_record(self, records):
        """
        Handles registration of a down path.
        """
        if not records.pcbs:
            return

        paths_to_propagate = []
        for pcb in records.pcbs:
            dst_ad = pcb.get_last_ad().ad_id
            dst_isd = pcb.get_last_ad().spcbf.isd_id

            if (self.down_segments.insert(pcb, self.topology.isd_id,
                self.topology.ad_id, dst_isd, dst_ad) is not None):
                paths_to_propagate.append(pcb)
                logging.info("Down-Path registered (%d, %d)", dst_isd, dst_ad)
            else:
                logging.info("Down-Path to (%d, %d) already known.",
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

    def _handle_core_segment_record(self, records):
        """
        Handles registration of a core path.
        """
        if not records.pcbs:
            return

        for pcb in records.pcbs:
            src_ad = pcb.get_first_ad().ad_id
            src_isd = pcb.get_first_ad().spcbf.isd_id
            dst_ad = pcb.get_last_ad().ad_id
            dst_isd = pcb.get_last_ad().spcbf.isd_id
            self.core_segments.insert(pcb, src_isd=src_isd, src_ad=src_ad,
                                      dst_isd=dst_isd, dst_ad=dst_ad)
#             logging.info("Core-Path registered: (%d, %d) -> (%d, %d)",
#                          src_isd, src_ad, dst_isd, dst_ad)

        # Send pending requests that couldn't be processed due to the lack of
        # a core path to the destination PS.
        if self.waiting_targets:
            pcb = records.pcbs[0]
            next_hop = self.ifid2addr[pcb.get_first_ad().hof.egress_if]
            path = pcb.get_path()
            targets = copy.deepcopy(self.waiting_targets)
            for (target_isd, target_ad, info) in targets:
                if target_isd == dst_isd and target_ad == dst_ad:
                    path_request = PathSegmentRequest.from_values(self.addr,
                                                                  info, path)
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
                    records = PathSegmentRecords.from_values(self.addr,
                                                             path_info,
                                                             path_segments,
                                                             cpath)
                    records.hdr.set_downpath()
                    if_id = cpath.get_first_hop_of().egress_if
                    next_hop = self.ifid2addr[if_id]
                    logging.info("Sending down-path to CPS in (%d, %d).",
                                 router.interface.neighbor_isd,
                                 router.interface.neighbor_ad)
                    self.send(records, next_hop)

    def handle_path_request(self, path_request):
        assert isinstance(path_request, PathSegmentRequest)
        dst_isd = path_request.info.dst_isd
        dst_ad = path_request.info.dst_ad
        ptype = path_request.info.type
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
                            [path_request])
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
                            [path_request])
                cpaths = self.core_segments(src_isd=self.topology.isd_id,
                                            src_ad=self.topology.ad_id,
                                            dst_isd=dst_isd)
                if cpaths:
                    path = cpaths[0].get_path()
                    if_id = path.get_first_hop_of().egress_if
                    next_hop = self.ifid2addr[if_id]
                    request = PathSegmentRequest.from_values(self.addr,
                                                             path_request.info,
                                                             path)
                    request.hdr.set_downpath()
                    self.send(request, next_hop)
                    logging.info("Down-Path request for different ISD. "
                                 "Forwarding request to CPS in (%d, %d).",
                                 cpaths[0].get_last_ad().spcbf.isd_id,
                                 cpaths[0].get_last_ad().ad_id)
                # If no core_path was available, add request to waiting targets.
                else:
                    self.waiting_targets.add((dst_isd, dst_ad,
                                              path_request.info))
        elif ptype == PST.CORE:
            src_isd = path_request.info.src_isd
            src_ad = path_request.info.src_ad
            key = ((src_isd, src_ad), (dst_isd, dst_ad))
            paths = self.core_segments(src_isd=src_isd, src_ad=src_ad,
                                       dst_isd=dst_isd, dst_ad=dst_ad)
            if paths:
                segments_to_send.extend(paths)
            else:
                update_dict(self.pending_core, key, [path_request])
                logging.info("No core-segment for (%d, %d) -> (%d, %d), "
                             "request is pending.", src_isd, src_ad,
                             dst_isd, dst_ad)
        else:
            logging.error("CPS received unsupported path request!.")

        if segments_to_send:
            self.send_path_segments(path_request, segments_to_send)


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

    def _handle_up_segment_record(self, records):
        """
        Handles Up Path registration from local BS.
        """
        if not records.pcbs:
            return
        for pcb in records.pcbs:
            self.up_segments.insert(pcb, self.topology.isd_id,
                                    self.topology.ad_id,
                                    pcb.get_first_ad().spcbf.isd_id,
                                    pcb.get_first_ad().ad_id)
            logging.info("Up-Segment to (%d, %d) registered.",
                         pcb.get_first_ad().spcbf.isd_id,
                         pcb.get_first_ad().ad_id)

        # Sending pending targets to the core using first registered up-path.
        if self.waiting_targets:
            pcb = records.pcbs[0]
            path = pcb.get_path(reverse_direction=True)
            if_id = path.get_first_hop_of().egress_if
            next_hop = self.ifid2addr[if_id]
            targets = copy.deepcopy(self.waiting_targets)
            for (isd, ad, info) in targets:
                path_request = PathSegmentRequest.from_values(self.addr, info,
                                                              path)
                self.send(path_request, next_hop)
                logging.info("PATH_REQ sent using (first) registered up-path")
                self.waiting_targets.remove((isd, ad, info))

        # Handling pending UP_PATH requests.
        for path_request in self.pending_up:
            self.send_path_segments(path_request, self.up_segments())
        self.pending_up = []

    def _handle_core_segment_record(self, records):
        """
        Handles registration of a core path.
        """
        if not records.pcbs:
            return

        for pcb in records.pcbs:
            src_ad = pcb.get_first_ad().ad_id
            src_isd = pcb.get_first_ad().spcbf.isd_id
            dst_ad = pcb.get_last_ad().ad_id
            dst_isd = pcb.get_last_ad().spcbf.isd_id
            self.core_segments.insert(pcb, src_isd=src_isd, src_ad=src_ad,
                                      dst_isd=dst_isd, dst_ad=dst_ad)
            logging.info("Core-Segment registered: (%d, %d) -> (%d, %d)",
                         src_isd, src_ad, dst_isd, dst_ad)

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
            path.up_segment_info.up_flag = True # FIXME: temporary hack. A very
            # first path is _always_ down-path, any subsequent is up-path.
            if_id = path.get_first_hop_of().ingress_if
            next_hop = self.ifid2addr[if_id]
            path_request = PathSegmentRequest.from_values(self.addr, info, path)
            self.send(path_request, next_hop)

    def handle_path_request(self, path_request):
        """
        Handles all types of path request.
        """
        assert isinstance(path_request, PathSegmentRequest)
        dst_isd = path_request.info.dst_isd
        dst_ad = path_request.info.dst_ad
        ptype = path_request.info.type
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
                                [path_request])
                    self.waiting_targets.add((dst_isd, dst_ad))
                else:  # PST.UP
                    self.pending_up.append(path_request)
                return

        # Requester wants down-path.
        if (ptype in [PST.DOWN, PST.UP_DOWN]):
            paths = self.down_segments(dst_isd=dst_isd, dst_ad=dst_ad)
            if paths:
                paths_to_send.extend(paths)
            else:
                update_dict(self.pending_down,
                            (dst_isd, dst_ad),
                            [path_request])
                self._request_paths_from_core(PST.DOWN, dst_isd, dst_ad)
                logging.info("No downpath, request is pending.")

        # Requester wants core-path.
        if ptype == PST.CORE:
            src_isd = path_request.info.src_isd
            src_ad = path_request.info.src_ad
            paths = self.core_segments(src_isd=src_isd, src_ad=src_ad,
                                       dst_isd=dst_isd, dst_ad=dst_ad)
            if paths:
                paths_to_send.extend(paths)
            else:
                update_dict(self.pending_core,
                            ((src_isd, src_ad), (dst_isd, dst_ad)),
                            [path_request])
                self._request_paths_from_core(PST.CORE, dst_isd, dst_ad,
                                              src_isd, src_ad)

        if paths_to_send:
            self.send_path_segments(path_request, paths_to_send)


def main():
    """
    Main function.
    """
    logging.basicConfig(level=logging.DEBUG)
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
    path_server.run()

if __name__ == "__main__":
    main()
