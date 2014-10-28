	"""
cert_server.py

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
        Beacon, PathRequest, PathRecord, PathInfo
from lib.packet.scion import PacketType as PT
from lib.topology import ElementType, NeighborType
from infrastructure.server import ServerBase, SCION_UDP_PORT,\
        SCION_UDP_PS2EH_PORT 
import socket
import sys

#def update_dict(dictionary, key, values, elem_num=0):
#    if key in dictionary:
#        dictionary[key].extend(values)
#    else:
#        dictionary[key] = values 
#    dictionary[key] = dictionary[key][-elem_num:]


class CertServer(ServerBase):
    """
    The SCION Certificate Server.
    """
    def __init__(self, addr, topo_file, config_file, rot_file):
        ServerBase.__init__(self, addr, topo_file, config_file, rot_file)

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
        print ("Sending to PATH_REP, using path:",path, next_hop)
        self.send(path_reply, next_hop, port)

    def request_core(self, isd, ad):
        if not self.up_paths:
            self.pending_targets.add((isd,ad))
        else:
            pcb = self.up_paths[-1]
            next_hop = self.ifid2addr[pcb.rotf.if_id]
            path=pcb.get_core_path()
            info = PathInfo.from_values(PathInfo.DOWN_PATH, isd, ad)
            path_request = PathRequest.from_values(self.addr, info, path)
            self.send(path_request, next_hop)


    def handle_path_request(self, packet):
        print("PATH_REQ")
        #TODO inter isd request: if isd != myisd
        path_request = PathRequest(packet) 
        isd = path_request.info.isd 
        ad = path_request.info.ad 
        type = path_request.info.type

        paths_to_send  = []
        print (isd,ad)
        print(self.down_paths)

        if (type in [PathInfo.UP_PATH, PathInfo.BOTH_PATHS] and not
            self.topology.is_core_ad):
            if self.up_paths:
                paths_to_send.extend(self.up_paths)
            else:
                return

        if (type == PathInfo.DOWN_PATH or (type == PathInfo.BOTH_PATHS and not
            self.topology.is_core_ad)):
            if (isd, ad) in self.down_paths:
                paths_to_send.extend(self.down_paths[(isd, ad)])
            else:
                if not self.topology.is_core_ad:
                    self.request_core(isd, ad)
                elif isd != self.topology.isd_id:
                    self.request_isd(isd,ad)
                print("No downpath, request is pending.")
                paths_to_send = []
                update_dict(self.pending_requests, (isd, ad), [path_request])
        else:
            print("ERROR: Wrong path request")

        if paths_to_send:
            self.send_paths(path_request, paths_to_send)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)

        if ptype == PT.ROT_REQ_LOCAL:
            self.handle_local_request(packet)
        elif ptype == PT.CERT_REQ:
            self.handle_cert_request(packet)
        elif ptype == PT.ROT_REQ:
            self.handle_rot_request(packet)
        else: 
            print("Type %d not supported.", ptype)

def main():
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv)!=5:
        print("run: %s IP topo_file conf_file rot_file" %sys.argv[0])
        sys.exit()
    cs=CertServer(IPv4HostAddr(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4])
    cs.run()

if __name__ == "__main__":
    main()
