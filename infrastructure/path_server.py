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
from lib.packet.pcb import *
from lib.packet.opaque_field import *
from lib.packet.path import EmptyPath 
from lib.packet.scion import SCIONPacket, IFIDRequest, IFIDReply, get_type,\
        UpPath, DownPath, Beacon, PathRequest, PathReply, PathInfo
from lib.packet.scion import PacketType as PT
from lib.topology import ElementType, NeighborType
from infrastructure.server import ServerBase, SCION_UDP_PORT,\
        SCION_UDP_PS2EH_PORT 
import socket
import sys

PATHS_NO = 5 #TODO replace by configuration parameter

def update_dict(dictionary, key, values):
    if key in dictionary:
        dictionary[key].extend(values)
    else:
        dictionary[key] = values 


class PathServer(ServerBase):
    """
    The SCION Beacon Server.
    """
    def __init__(self, addr, topo_file, config_file):
        ServerBase.__init__(self, addr, topo_file, config_file)
        self.up_paths = []
        self.down_paths = {}
        #TODO replace by pathstore instance
        self.pending_requests = {}#TODO three classes
        self.pending_targets = set() #used when local PS does not have uppath

    def handle_up_path(self, packet):
        """
        Handles Up Path registration from local BS. 
        """
        if self.config.is_core_ad:
            print ("ERROR: uppath registration in core")
            return
        pcb = UpPath(packet).pcb
        self.up_paths.append(pcb)
        print("Up-Path Registered")
        if self.pending_targets:
            next_hop = self.ifid2addr[pcb.rotf.if_id]
            path = pcb.get_core_path()
            for (isd, ad) in self.pending_targets:
                info = PathInfo.from_values(isd, ad, PathInfo.DOWN_PATH)
                path_request = PathRequest.from_values(self.addr, info, path)
                self.send(path_request, next_hop)
                print("PathRequest sent using (first) registered up-path")
            self.pending_targets.clear()

    #TODO: MOVE it to server?
#change [0] to current? check it
    def get_first_hop(self, spkt):
        if isinstance(spkt.hdr.path, EmptyPath):
            return (spkt.hdr.dst_addr, SCION_UDP_PS2EH_PORT) 
        else:
            of = spkt.hdr.path.down_path_hops[0]
            return (self.ifid2addr[of.egress_if], SCION_UDP_PORT)

    def send_paths(self, path_request, isd, ad):
        """
        Sends downpath and optionally uppath (depending on server's location)
        """
        dst = path_request.hdr.src_addr
        if not self.config.is_core_ad:
            if not self.up_paths:
                print ("ERROR: no uppath while downpath exists")
            else:
                pcb = self.up_paths[-1]
                up_path = UpPath.from_values(self.addr, pcb)
                self.send(up_path, dst)

        pcb = self.down_paths[(isd, ad)][-1] #TODO multiple paths
        path_request.hdr.path.reverse()
        path = path_request.hdr.path 
        path_reply = PathReply.from_values(dst, path_request.info, pcb, path)
        path_reply.hdr.set_downpath()
        (next_hop, port) = self.get_first_hop(path_reply)
        print ("Sending to PATH_REP")

#TODO remove if when clientdaemo is ready
        if (port == SCION_UDP_PS2EH_PORT):
            path_reply.set_payload(path_reply.pcb.pack()[:8] +
                    path_reply.pcb.pack()[16:])

        self.send(path_reply, next_hop, port)

    def request_core(self, isd, ad):
        if not self.up_paths:
            self.pending_targets.add((isd,ad))
        else:
            pcb = self.up_paths[-1]
            next_hop = self.ifid2addr[pcb.rotf.if_id]
            path=pcb.get_core_path()
            info = PathInfo.from_values(isd, ad, PathInfo.DOWN_PATH)
            path_request = PathRequest.from_values(self.addr, info, path)
            self.send(path_request, next_hop)

    def handle_path_request(self, packet):
        print("PATH_REQ")
        #TODO inter isd request: if isd != myisd
        path_request = PathRequest(packet) 
        isd = path_request.info.isd 
        ad = path_request.info.ad 
        print (isd,ad)
        print(self.down_paths)
        if (isd, ad) in self.down_paths:
            self.send_paths(path_request, isd, ad)
        else:
            update_dict(self.pending_requests, (isd, ad), [path_request])
            print("No downpath, request is pending.")
            if not self.config.is_core_ad:
                self.request_core(isd, ad)

    def update_down_paths(self, isd_ad, pcbs):
        update_dict(self.down_paths, isd_ad, pcbs)
        self.down_paths[isd_ad] = self.down_paths[isd_ad][:PATHS_NO]

    def handle_path_reply(self, packet):
        path_reply = PathReply(packet)
        if path_reply.type != PathInfo.DOWN_PATH:
            print("ERROR: PathReply with UP_PATH.")
            return
        isd = path_reply.info.isd
        ad = path_reply.info.ad
        pcb = path_reply.pcb
        self.update_down_paths((isd, ad), [pcb])
        print(self.down_paths)
        print("PATH_REP:", isd, ad)

    def handle_path_registration(self, packet):
        if not self.config.is_core_ad:
            print("Error: downpath path registration at non-core.")
            return
        pcb = DownPath(packet).pcb
        isd = pcb.get_isd()
        ad = pcb.get_last_ad() 
        update_dict(self.down_paths, (isd, ad), [pcb])
        print("PATH_REG", isd, ad)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)

        if ptype == PT.PATH_REQ:
            self.handle_path_request(packet)
        elif ptype == PT.UP_PATH:
            self.handle_up_path(packet)
        elif ptype == PT.PATH_REP:
            self.handle_path_reply(packet)
        elif ptype == PT.PATH_REG:
            self.handle_path_registration(packet)
        else: 
            print("Type %d not supported.", ptype)

def main():
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv)!=4:
        print("run: %s IP topo_file conf_file" %sys.argv[0])
        sys.exit()
    ps=PathServer(IPv4HostAddr(sys.argv[1]), sys.argv[2], sys.argv[3])
    ps.run()

if __name__ == "__main__":
    main()
