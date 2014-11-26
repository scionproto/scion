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
from lib.packet.scion import SCIONPacket, get_type, PathRequest, PathRecord,\
PathInfo
from lib.packet.scion import PacketType as PT
from infrastructure.server import ServerBase, SCION_UDP_PORT
import sys
import logging

PATHS_NO = 5 #TODO replace by configuration parameter

def update_dict(dictionary, key, values, elem_num=0):
    """
    Updates dictionary. Used in managing as temporary paths' cache.
    """
    if key in dictionary:
        dictionary[key].extend(values)
    else:
        dictionary[key] = values
    dictionary[key] = dictionary[key][-elem_num:]


class PathServer(ServerBase):
    """
    The SCION Path Server.
    """
    def __init__(self, addr, topo_file, config_file):
        ServerBase.__init__(self, addr, topo_file, config_file)
        self.up_paths = []
        self.down_paths = {}
        #TODO replace by pathstore instance
        self.pending_requests = {}#TODO three classes
        self.pending_targets = set() #used when local PS does not have uppath

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

        if self.pending_targets:
            pcb = pcbs[0]
            next_hop = self.ifid2addr[pcb.rotf.if_id]
            path = pcb.get_core_path()
            for (isd, ad) in self.pending_targets:
                info = PathInfo.from_values(PathInfo.DOWN_PATH, isd, ad)
                path_request = PathRequest.from_values(self.addr, info, path)
                self.send(path_request, next_hop)
                logging.info("PATH_REQ sent using (first) registered up-path")
            self.pending_targets.clear()
        #TODO Handle DOWN_PATH pending_requests here

    def get_first_hop(self, spkt):
    #TODO: move it somewhere (server.py ?)
        """
        Returns first hop addr of down-path or end-host addr.
        """
        if isinstance(spkt.hdr.path, EmptyPath):
            return (spkt.hdr.dst_addr, SCION_UDP_PORT)
        else:
            #TODO change [0] to current?
            of = spkt.hdr.path.down_path_hops[0]
            return (self.ifid2addr[of.egress_if], SCION_UDP_PORT)

    def send_paths(self, path_request, paths):
        """
        Sends paths to requester (depending on server's location)
        """
        dst = path_request.hdr.src_addr
        path_request.hdr.path.reverse()
        path = path_request.hdr.path
        path_reply = PathRecord.from_values(dst, path_request.info, paths, path)
        path_reply.hdr.set_downpath()
        (next_hop, port) = self.get_first_hop(path_reply)
        logging.warning("Sending PATH_REP, using path: %s", path)
        self.send(path_reply, next_hop, port)

    def request_core(self, isd, ad):
        """
        Tries to request core PS for given target (isd, ad).
        """
        if not self.up_paths:
            logging.warning('Pending target added')
            self.pending_targets.add((isd, ad))
        else:
            pcb = self.up_paths[-1]
            next_hop = self.ifid2addr[pcb.rotf.if_id]
            path = pcb.get_core_path()
            info = PathInfo.from_values(PathInfo.DOWN_PATH, isd, ad)
            path_request = PathRequest.from_values(self.addr, info, path)
            self.send(path_request, next_hop)

    def request_isd(self, isd, ad):
        """
        TODO define inter-ISD requesting and implement function.
        """
        logging.warning("request_isd(): to implement")

    def handle_path_request(self, packet):
        """
        Handles all types of path request.
        """
        logging.info("PATH_REQ")
        path_request = PathRequest(packet)
        isd = path_request.info.isd
        ad = path_request.info.ad
        type = path_request.info.type

        paths_to_send = []

        if (type in [PathInfo.UP_PATH, PathInfo.BOTH_PATHS] and not
            self.topology.is_core_ad):
            if self.up_paths:
                paths_to_send.extend(self.up_paths)
            else:
                update_dict(self.pending_requests, (isd, ad), [path_request])
                self.pending_targets.add((isd, ad))
                return

        if (type == PathInfo.DOWN_PATH or (type == PathInfo.BOTH_PATHS and not
            self.topology.is_core_ad)):
            if (isd, ad) in self.down_paths:
                paths_to_send.extend(self.down_paths[(isd, ad)])
            else:
                if not self.topology.is_core_ad:
                    self.request_core(isd, ad)
                elif isd != self.topology.isd_id:
                    self.request_isd(isd, ad)
                logging.warning("No downpath, request is pending.")
                paths_to_send = []
                update_dict(self.pending_requests, (isd, ad), [path_request])
        else:
            logging.error("Wrong path request.")

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
            logging.warning("PATH_REG (%d, %d)", isd, ad)

        #serve pending requests
        if isd and ad and (isd, ad) in self.pending_requests:
            paths_to_send = []
            for path_request in self.pending_requests[(isd, ad)]:
                if path_request.info.type in [PathInfo.UP_PATH,
                        PathInfo.BOTH_PATHS]:
                    paths_to_send.extend(self.up_paths)
                paths_to_send.extend(self.down_paths[(isd, ad)])
                self.send_paths(path_request, paths_to_send)
            del self.pending_requests[(isd, ad)]

    def dispatch_path_record(self, packet):
        """
        Dispatches path record packet.
        """
        rec = PathRecord(packet)
        if rec.info.type == PathInfo.UP_PATH and not self.topology.is_core_ad:
            self.handle_up_path(rec)
        if rec.info.type == PathInfo.DOWN_PATH:
            self.handle_down_path(rec)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)

        if ptype == PT.PATH_REQ:
            self.handle_path_request(packet)
        elif ptype == PT.PATH_REP:
            self.dispatch_path_record(packet)
        else:
            logging.warning("Type %d not supported.", ptype)

def main():
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 4:
        logging.error("run: %s IP topo_file conf_file", sys.argv[0])
        sys.exit()
    ps = PathServer(IPv4HostAddr(sys.argv[1]), sys.argv[2], sys.argv[3])
    ps.run()

if __name__ == "__main__":
    main()
