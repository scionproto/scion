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
import copy
from infrastructure.scion_elem import SCIONElement, SCION_UDP_PORT
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.path import EmptyPath
from lib.packet.pcb import HalfPathBeacon
from lib.packet.scion import (SCIONPacket, get_type, PathRequest, PathRecords,
    PathInfo, PathInfoType as PIT)
from lib.packet.scion import PacketType as PT
from lib.topology import NeighborType
from lib.util import update_dict
import logging
import sys


PATHS_NO = 5  # TODO replace by configuration parameter


class PathServer(SCIONElement):
    """
    The SCION Path Server.
    """
    def __init__(self, addr, topo_file, config_file):
        SCIONElement.__init__(self, addr, topo_file, config_file)
        # TODO replace by pathstore instance
        self.down_paths = defaultdict(list)
        self.core_paths = defaultdict(list)

        self.pending_down = {}  # Dict of pending DOWN _and_ ALL requests.
        self.pending_core = {}

        self.waiting_targets = set()  # Used when local PS doesn't have up-path.
        # TODO replace by some cache data struct. (expiringdict ?)

    def _handle_up_path_record(self, path_record):
        """
        Handles Up Path registration from local BS.
        """
        pass

    def _handle_down_path_record(self, path_record):
        """
        Handles registration of a down path.
        """
        isd = None
        ad = None
        for pcb in path_record.pcbs:
            ad = pcb.get_last_ad()
            isd_id = ad.spcbf.isd_id
            update_dict(self.down_paths, (isd_id, ad.ad_id), [pcb], PATHS_NO)
            logging.info("Down-Path registered (%d, %d)", isd_id, ad.ad_id)

        # serve pending requests
        target = (isd, ad.ad_id)
        if isd is not None and ad is not None and target in self.pending_down:
            paths_to_send = []
            for path_request in self.pending_down[target]:
                paths_to_send.extend(self.down_paths[target])
                self.send_paths(path_request, paths_to_send)
            del self.pending_down[target]

    def _handle_core_path_record(self, path_record):
        """
        Handles a core_path record.
        """
        pass

    def _update_paths(self, paths, key, new_path):
        """
        Updates a received path in the path store. A path is only updated if
        it's fresher than previously seen paths.

        :param paths: The path store to use.
        :type paths: dict
        :parma key: The key in the path store.
        :type key: tuple
        :param new_path: The new path to be added to the path store.
        :type new_path: :class:`HalfPathBeacon`
        """
        assert isinstance(new_path, HalfPathBeacon)
        # NOTE: This function should be eventually moved to the PathStore class.
        if key not in paths or new_path not in paths[key]:
            update_dict(paths, key, [new_path], PATHS_NO)
            return True
        else:
            return False

    def send_paths(self, path_request, paths):
        """
        Sends paths to requester (depending on Path Server's location)
        """
        dst = path_request.hdr.src_addr
        path_request.hdr.path.reverse()
        path = path_request.hdr.path
        path_reply = PathRecords.from_values(dst, path_request.info,
                                             paths, path)
        path_reply.hdr.set_downpath()
        (next_hop, port) = self.get_first_hop(path_reply)
        logging.info("Sending PATH_REC, using path: %s", path)
        self.send(path_reply, next_hop, port)

    def dispatch_path_record(self, rec):
        """
        Dispatches path record packet.
        """
        assert isinstance(rec, PathRecords)
        if rec.info.type == PIT.UP:
            self._handle_up_path_record(rec)
        elif rec.info.type == PIT.DOWN:
            self._handle_down_path_record(rec)
        elif rec.info.type == PIT.CORE:
            self._handle_core_path_record(rec)
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
            self.handle_path_request(PathRequest(packet))
        elif ptype == PT.PATH_REC:
            self.dispatch_path_record(PathRecords(packet))
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

    def _handle_up_path_record(self, path_record):
        PathServer._handle_up_path_record(self, path_record)
        logging.error("Core Path Server received up-path record!")

    def _handle_down_path_record(self, path_record):
        """
        Handles registration of a down path.
        """
        if not path_record.pcbs:
            return

        paths_to_propagate = []
        for pcb in path_record.pcbs:
            dst_ad = pcb.get_last_ad().ad_id
            dst_isd = pcb.get_last_ad().spcbf.isd_id

            if self._update_paths(self.down_paths, (dst_isd, dst_ad), pcb):
                paths_to_propagate.append(pcb)
                logging.info("Down-Path registered (%d, %d)", dst_isd, dst_ad)
            else:
                logging.info("Down-Path to (%d, %d) already known.",
                             dst_isd, dst_ad)

        # For now we let every CPS know about all the down-paths within an ISD.
        if paths_to_propagate:
            self._propagate_down_paths(paths_to_propagate, path_record.info)

        # Serve pending requests.
        target = (dst_isd, dst_ad)
        if target in self.pending_down:
            paths_to_send = []
            for path_request in self.pending_down[target]:
                paths_to_send.extend(self.down_paths[target])
                self.send_paths(path_request, paths_to_send)
            del self.pending_down[target]


    def _handle_core_path_record(self, path_record):
        """
        Handles registration of a core path.
        """
        if not path_record.pcbs:
            return

        for pcb in path_record.pcbs:
            src_ad = pcb.get_first_ad().ad_id
            src_isd = pcb.get_first_ad().spcbf.isd_id
            dst_ad = pcb.get_last_ad().ad_id
            dst_isd = pcb.get_last_ad().spcbf.isd_id
            key = ((src_isd, src_ad), (dst_isd, dst_ad))
            update_dict(self.core_paths, key, [pcb], PATHS_NO)
            logging.info("Core-Path registered: (%d, %d) -> (%d, %d)",
                         src_isd, src_ad, dst_isd, dst_ad)

        # Send pending requests that couldn't be processed due to the lack of
        # a core path to the destination PS.
        if self.waiting_targets:
            pcb = path_record.pcbs[0]
            next_hop = self.ifid2addr[pcb.get_first_ad().hof.egress_if]
            path = pcb.get_path()
            targets = copy.deepcopy(self.waiting_targets)
            for (target_isd, target_ad, info) in targets:
                if target_isd == dst_isd and target_ad == dst_ad:
                    path_request = PathRequest.from_values(self.addr,
                                                           info, path)
                    self.send(path_request, next_hop)
                    self.waiting_targets.remove((target_isd, target_ad, info))
                    logging.debug("Sending path request %s on newly learned "
                                  "path to (%d, %d)", info, dst_isd, dst_ad)

        # Serve pending core path requests.
        target = ((src_isd, src_ad), (dst_isd, dst_ad))
        if target in self.pending_core:
            paths_to_send = []
            for path_request in self.pending_core[target]:
                paths_to_send.extend(self.core_paths[target])
                self.send_paths(path_request, paths_to_send)
            del self.pending_core[target]

    def _propagate_down_paths(self, paths, path_info):
        """
        Propagate down paths to other CPSes in the same ISD.
        """
        # FIXME: For new we broadcast the path to every CPS in the core, even
        # the one we just received it from. Can we avoid that?
        for router in self.topology.routers[NeighborType.ROUTING]:
            if router.interface.neighbor_isd == self.topology.isd_id:
                key = ((self.topology.isd_id, self.topology.ad_id),
                       (router.interface.neighbor_isd,
                        router.interface.neighbor_ad))
                cpath = None
                if key in self.core_paths:
                    cpath = self.core_paths[key][0].get_path()
                    records = PathRecords.from_values(self.addr, path_info,
                                                      paths, cpath)
                    if_id = cpath.get_first_hop_of().egress_if
                    next_hop = self.ifid2addr[if_id]
                    logging.info("Sending down-path to CPS in (%d, %d).",
                                 router.interface.neighbor_isd,
                                 router.interface.neighbor_ad)
                    self.send(records, next_hop)

    def handle_path_request(self, path_request):
        assert isinstance(path_request, PathRequest)
        logging.info("PATH_REQ received")
        dst_isd = path_request.info.dst_isd
        dst_ad = path_request.info.dst_ad
        type = path_request.info.type

        paths_to_send = []
        if type == PIT.UP:
            logging.warning("CPS received up path request! This should not "
                            "happen")
            return
        elif type == PIT.DOWN:
            if (dst_isd, dst_ad) in self.down_paths:
                paths_to_send.extend(self.down_paths[(dst_isd, dst_ad)])
            elif dst_isd == self.topology.isd_id:
                update_dict(self.pending_down,
                            (dst_isd, dst_ad),
                            [path_request])
                logging.info("No downpath for (%d, %d), request is pending.",
                             dst_isd, dst_ad)
                # TODO Sam: Here we should ask other CPSes in the same ISD for
                # the down-path. We first need to decide how to replicate
                # CPS state.
            else:
                # Destination is in a different ISD. Ask a CPS in a this ISD for
                # a down-path using the first available core path.
                update_dict(self.pending_down,
                            (dst_isd, dst_ad),
                            [path_request])
                core_path_available = False
                for pcb in self.core_paths:
                    if pcb.get_last_ad().spcbf.isd_id == dst_isd:
                        path = pcb.get_path()
                        if_id = path.get_first_hop_of().egress_if
                        next_hop = self.ifid2addr[if_id]
                        request = PathRequest.from_values(self.addr,
                                                          path_request.info,
                                                          path)
                        self.send(request, next_hop)
                        logging.info("Down-Path request for different ISD. "
                                     "Forwarding request to CPS in (%d, %d).",
                                     pcb.get_last_ad().spcbf.isd_id,
                                     pcb.get_last_ad().ad_id)
                        core_path_available = True
                        break
                # If no core_path was available, add request to waiting targets.
                if not core_path_available:
                    self.waiting_targets.add((dst_isd, dst_ad,
                                              path_request.info))
        elif type == PIT.CORE:
            src_isd = path_request.info.src_isd
            src_ad = path_request.info.dst_ad
            key = ((src_isd, src_ad), (dst_isd, dst_ad))
            if key in self.core_paths:
                paths_to_send.extend(self.core_paths[key])
            else:
                update_dict(self.core_paths, key, [path_request])
                logging.info("No corepath for (%d, %d) -> (%d, %d), request is "
                             "pending.", src_isd, src_ad, dst_isd, dst_ad)
        else:
            logging.error("CPS received unsupported path request!.")

        if paths_to_send:
            self.send_paths(path_request, paths_to_send)


class LocalPathServer(PathServer):
    """
    SCION Path Server in a non-core AD. Stores up-paths to the core and
    registers down-paths with the CPS. Can cache paths learned from a CPS.
    """
    def __init__(self, addr, topo_file, config_file):
        PathServer.__init__(self, addr, topo_file, config_file)
        # Sanity check that we should indeed be a local path server.
        assert not self.topology.is_core_ad, "This shouldn't be a local PS!"

        self.up_paths = []  # List of up-paths to the core.
        self.pending_up = []  # List of pending UP requests.

    def _handle_up_path_record(self, path_record):
        """
        Handles Up Path registration from local BS.
        """
        if not path_record.pcbs:
            return
        pcbs = path_record.pcbs
        self.up_paths.extend(pcbs)
        self.up_paths = self.up_paths[-PATHS_NO:]
        logging.info("Up-Path Registered")

        # Sending pending targets to the core using first registered up-path.
        if self.waiting_targets:
            pcb = pcbs[0]
            path = pcb.get_path(reversed_direction=True)
            if_id = path.get_first_hop_of().egress_if
            next_hop = self.ifid2addr[if_id]
            targets = copy.deepcopy(self.waiting_targets)
            for (isd, ad, info) in targets:
                path_request = PathRequest.from_values(self.addr, info, path)
                self.send(path_request, next_hop)
                logging.info("PATH_REQ sent using (first) registered up-path")
                self.waiting_targets.remove((isd, ad, info))

        # Handling pending UP_PATH requests.
        for path_request in self.pending_up:
            self.send_paths(path_request, self.up_paths)
        self.pending_up = []

    def _request_paths_from_core(self, type, dst_isd, dst_ad,
                                 src_isd=None, src_ad=None):
        """
        Tries to request core PS for given target (isd, ad).
        """
        if src_isd is None:
            src_isd = self.topology.isd_id
        if src_ad is None:
            src_ad = self.topology.ad_id

        info = PathInfo.from_values(PIT.DOWN, src_isd, dst_isd,
                                    src_ad, dst_ad)

        if not self.up_paths:
            logging.info('Pending target added')
            self.waiting_targets.add((dst_isd, dst_ad, info))
        else:
            logging.info('Requesting path from core.')
            pcb = self.up_paths[-1]
            path = pcb.get_path(reverse_direction=True)
            if_id = path.get_first_hop_of().ingress_if
            next_hop = self.ifid2addr[if_id]
            path_request = PathRequest.from_values(self.addr, info, path)
            self.send(path_request, next_hop)

    def handle_path_request(self, path_request):
        """
        Handles all types of path request.
        """
        assert isinstance(path_request, PathRequest)
        logging.info("PATH_REQ received")
        dst_isd = path_request.info.dst_isd
        dst_ad = path_request.info.dst_ad
        type = path_request.info.type

        paths_to_send = []

        # Requester wants up-path.
        if type in [PIT.UP, PIT.ALL]:
            if self.up_paths:
                paths_to_send.extend(self.up_paths)
            else:
                if type == PIT.ALL:
                    update_dict(self.pending_down,
                                (dst_isd, dst_ad),
                                [path_request])
                    self.waiting_targets.add((dst_isd, dst_ad))
                else:  # PIT.UP
                    self.pending_up.append(path_request)
                return

        # Requester wants down-path.
        if (type in [PIT.DOWN, PIT.ALL]):
            if (dst_isd, dst_ad) in self.down_paths:
                paths_to_send.extend(self.down_paths[(dst_isd, dst_ad)])
            else:
                self._request_paths_from_core(type, dst_isd, dst_ad)
                logging.info("No downpath, request is pending.")
                update_dict(self.pending_down,
                            (dst_isd, dst_ad),
                            [path_request])

        # Requester wants core-path.
        if type == PIT.CORE:
            src_isd = path_request.info.src_isd
            src_ad = path_request.info.src_ad
            key = ((src_isd, src_ad), (dst_isd, dst_ad))
            if key in self.core_paths:
                paths_to_send.extend(self.core_paths[key])
            else:
                self._request_paths_from_core(PIT.CORE, dst_isd, dst_ad,
                                              src_isd, src_ad)

        if paths_to_send:
            self.send_paths(path_request, paths_to_send)


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
