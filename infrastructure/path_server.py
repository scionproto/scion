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

from lib.packet.host_addr import IPv4HostAddr
from lib.packet.path import EmptyPath
from lib.packet.scion import (SCIONPacket, get_type, PathRequest, PathRecords,
    PathInfo, PathInfoType as PIT)
from lib.packet.scion import PacketType as PT
from infrastructure.scion_elem import SCIONElement, SCION_UDP_PORT
from lib.util import update_dict
import sys
import logging

PATHS_NO = 5 #TODO replace by configuration parameter

class PathServer(SCIONElement):
    """
    The SCION Path Server.
    """
    def __init__(self, addr, topo_file, config_file):
        SCIONElement.__init__(self, addr, topo_file, config_file)
        #TODO replace by pathstore instance
        self.up_paths = []
        self.down_paths = {}
        self.pending_up = [] # List of pending UP requests. 
        self.pending_down = {} # Dictionary of pending DOWN _and_ BOTH requests.
        self.waiting_targets = set() # Used when local PS does not have up-path.
        #TODO replace by some cache data struct. (expiringdict ?)

    def handle_up_path(self, path_record):
        """
        Handles Up Path registration from local BS.
        """
        if not path_record.pcbs:
            return
        pcbs = path_record.pcbs
        self.up_paths.extend(pcbs)
        self.up_paths = self.up_paths[-PATHS_NO:]
        logging.info("Up-Path Registered")

        #Sending pending targets to the core using first registered up-path.
        if self.waiting_targets:
            pcb = pcbs[0]
            next_hop = self.ifid2addr[pcb.rotf.if_id]
            path = pcb.get_core_path()
            for (isd, ad) in self.waiting_targets:
                info = PathInfo.from_values(PIT.DOWN, isd, ad)
                path_request = PathRequest.from_values(self.addr, info, path)
                self.send(path_request, next_hop)
                logging.info("PATH_REQ sent using (first) registered up-path")
            self.waiting_targets.clear()

            # Handling pending UP_PATH requests.
            for path_request in self.pending_up:
                self.send_paths(path_request, self.up_paths)
            self.pending_up = []

    def send_paths(self, path_request, paths):
        """
        Sends paths to requester (depending on Path Server's location)
        """
        dst = path_request.hdr.src_addr
        path_request.hdr.path.reverse()
        path = path_request.hdr.path
        path_reply = PathRecords.from_values(dst, path_request.info, paths,
            path)
        path_reply.hdr.set_downpath()
        (next_hop, port) = self.get_first_hop(path_reply)
        logging.info("Sending PATH_REC, using path: %s", path)
        self.send(path_reply, next_hop, port)

    def request_paths_from_core(self, isd, ad):
        """
        Tries to request core PS for given target (isd, ad).
        """
        if not self.up_paths:
            logging.info('Pending target added')
            self.waiting_targets.add((isd, ad))
        else:
            logging.info('Requesting core for a down-path')
            pcb = self.up_paths[-1]
            next_hop = self.ifid2addr[pcb.rotf.if_id]
            path = pcb.get_core_path()
            info = PathInfo.from_values(PIT.DOWN, isd, ad)
            path_request = PathRequest.from_values(self.addr, info, path)
            self.send(path_request, next_hop)

    def request_isd(self, isd, ad):
        """
        TODO define inter-ISD requesting and implement function.
        """
        logging.warning("request_isd(): to implement")

    def handle_path_request(self, path_request):
        """
        Handles all types of path request.
        """
        assert isinstance(path_request, PathRequest)
        logging.info("PATH_REQ received")
        isd = path_request.info.isd
        ad = path_request.info.ad
        type = path_request.info.type

        paths_to_send = []

        # Not CPS and requester wants up-path.
        if (type in [PIT.UP, PIT.BOTH] and not self.topology.is_core_ad):
            if self.up_paths:
                paths_to_send.extend(self.up_paths)
            else:
                if type == PIT.BOTH:
                    update_dict(self.pending_down, (isd, ad), [path_request])
                    self.waiting_targets.add((isd, ad))
                else: # PIT.UP
                    self.pending_up.append(path_request)
                return

        # Requester wants down-path (notice that CPS serves only down-paths).
        if (type == PIT.DOWN or (type == PIT.BOTH and not
            self.topology.is_core_ad)):
            if (isd, ad) in self.down_paths:
                paths_to_send.extend(self.down_paths[(isd, ad)])
            else:
                if not self.topology.is_core_ad:
                    self.request_paths_from_core(isd, ad)
                elif isd != self.topology.isd_id:
                    self.request_isd(isd, ad)
                logging.warning("No downpath, request is pending.")
                paths_to_send = []
                update_dict(self.pending_down, (isd, ad), [path_request])

        if paths_to_send:
            self.send_paths(path_request, paths_to_send)

    def handle_down_path(self, path_record):
        """
        Handles registration of down path.
        """
        isd = None
        ad = None
        for pcb in path_record.pcbs:
            isd = pcb.get_isd()
            ad = pcb.get_last_ad()
            update_dict(self.down_paths, (isd, ad), [pcb], PATHS_NO)
            logging.info("PATH registered (%d, %d)", isd, ad)

        #serve pending requests
        target = (isd, ad)
        if isd is not None and ad is not None and target in self.pending_down:
            paths_to_send = []
            for path_request in self.pending_down[target]:
                if path_request.info.type == PIT.BOTH:
                    paths_to_send.extend(self.up_paths)
                paths_to_send.extend(self.down_paths[target])
                self.send_paths(path_request, paths_to_send)
            del self.pending_down[target]

    def dispatch_path_record(self, rec):
        """
        Dispatches path record packet.
        """
        assert isinstance(rec, PathRecords)
        if rec.info.type == PIT.UP and not self.topology.is_core_ad:
            self.handle_up_path(rec)
        elif rec.info.type == PIT.DOWN:
            self.handle_down_path(rec)
        else:
            logging.error("Wrong path record.")

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

def main():
    """
    Main function.
    """
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 4:
        logging.error("run: %s IP topo_file conf_file", sys.argv[0])
        sys.exit()
    ps = PathServer(IPv4HostAddr(sys.argv[1]), sys.argv[2], sys.argv[3])
    ps.run()

if __name__ == "__main__":
    main()
