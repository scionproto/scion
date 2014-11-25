"""
sciond.py

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
from lib.packet.path import EmptyPath, CorePath, PeerPath, CrossOverPath 
from lib.packet.scion import SCIONPacket, get_type, PathRequest, PathRecord,\
        PathInfo
from lib.packet.scion import PacketType as PT
from lib.topology import ElementType, NeighborType
from infrastructure.server import ServerBase, SCION_UDP_PORT,\
        SCION_UDP_PS2EH_PORT 
from infrastructure.path_server import update_dict
import socket
import sys
import threading
import copy

PATHS_NO = 5 #conf parameter?

class SCIONDaemon(ServerBase):
    """
    The SCION Daemon. 
    """

    TIMEOUT = 7 

    def __init__(self, addr, topo_file, config_file):
        ServerBase.__init__(self, addr, topo_file, config_file)
        #TODO replace by pathstore instance
        self.up_paths = []
        self.down_paths = {}
        self._waiting_targets = {}

#move it to beacon
    def build_core_path(self, up_path, down_path):
        if not up_path or not down_path or not up_path.ads or not down_path.ads:
            return None
#TODO sanity checks...

        core_path = CorePath()
        core_path.up_path_info = up_path.iof
        for block in reversed(up_path.ads):
            core_path.up_path_hops.append(copy.deepcopy(block.pcbm.hof))
        core_path.up_path_hops[-1].info = 0x20

        core_path.down_path_info = down_path.iof
        for block in down_path.ads:
            core_path.down_path_hops.append(copy.deepcopy(block.pcbm.hof))
        core_path.down_path_hops[0].info = 0x20
        return core_path

    def join_shortcuts(self, up_path, down_path, point, peer=True):
        """
        point: tuple (up_path_index, down_path_index) position of peer/xovr link
        peer:  true for peer, false for xovr path
        TODO
            update hops in Info OF
        """
        up_path = copy.deepcopy(up_path)
        down_path = copy.deepcopy(down_path)
        if peer:
            path = PeerPath()
            info = 0xf0
        else:
            path = CrossOverPath()
            info = 0xc0

        path.up_path_info = up_path.iof
        path.up_path_info.info = info
        path.up_path_info.hops -= point[0]
        for i in reversed(range(point[0], len(up_path.ads))):
            path.up_path_hops.append(up_path.ads[i].pcbm.hof)
        path.up_path_hops[-1].info = 0x20
        path.up_path_upstream_ad = up_path.ads[point[0]-1].pcbm.hof

        if peer:
            up_ad = up_path.ads[point[0]]
            down_ad = down_path.ads[point[1]]
            for up_peer in up_ad.pms:
                for down_peer in down_ad.pms:
                    if (up_peer.ad_id == down_ad.pcbm.ad_id and down_peer.ad_id
                            == up_ad.pcbm.ad_id):
                        path.up_path_peering_link = up_peer.hof 
                        path.down_path_peering_link = down_peer.hof 

        path.down_path_info = down_path.iof
        path.down_path_info.info = info
        path.down_path_info.hops -= point[1]
        path.down_path_upstream_ad = down_path.ads[point[1]-1].pcbm.hof 
        for i in range(point[1], len(down_path.ads)):
            path.down_path_hops.append(down_path.ads[i].pcbm.hof)
        path.down_path_hops[0].info = 0x20

        return path

    def build_short_path(self, up_path, down_path):
#TODO check if stub ADs are the same...
        if not up_path or not down_path or not up_path.ads or not down_path.ads:
            return None

        #looking for xovr and peer points
        xovrs = []
        peers = []
        for up_i in range(1, len(up_path.ads)):
            for down_i in range(1, len(down_path.ads)):
                up_ad = up_path.ads[up_i]
                down_ad = down_path.ads[down_i]
                if up_ad.pcbm.ad_id == down_ad.pcbm.ad_id:
                    xovrs.append((up_i, down_i))
                else:
                    for up_peer in up_ad.pms: 
                        for down_peer in down_ad.pms:
                            if (up_peer.ad_id == down_ad.pcbm.ad_id and
                                    down_peer.ad_id == up_ad.pcbm.ad_id):
                                peers.append((up_i, down_i))

        print ("xovr:", xovrs, "peers:", peers)
        print("Select shortest path xovrs (preferred) or peers")
        xovrs.sort(key=lambda tup: sum(tup))
        peers.sort(key=lambda tup: sum(tup))
        if not xovrs and not peers:
            return None
        elif xovrs and peers:
            if sum(peers[-1]) > sum(xovrs[-1]):
                return self.join_shortcuts(up_path, down_path, peers[-1], True) 
            else:
                return self.join_shortcuts(up_path, down_path, xovrs[-1], False)
        elif xovrs: 
            return self.join_shortcuts(up_path, down_path, xovrs[-1], False) 
        else: #peers only
            return self.join_shortcuts(up_path, down_path, peers[-1], True) 

    def build_fullpaths(self, up_paths, down_paths):
        """
        TODO
        """
        short_paths = []
        core_paths = []
        for up in up_paths:
            for down in down_paths:
                path = self.build_short_path(up, down)
                if path and path not in short_paths:
                    short_paths.append(path)
                path = self.build_core_path(up, down)
                if path and path not in core_paths:
                    core_paths.append(path)
        return short_paths + core_paths

    def request_paths(self, type, isd, ad):
        info = PathInfo.from_values(type, isd, ad)
        path_request = PathRequest.from_values(self.addr, info)
        dst = self.topology.servers[ElementType.PATH_SERVER].addr
        self.send(path_request, dst)
    
    def get_paths(self, isd, ad):
        """
        Returns list of paths
        """
        if self.up_paths and (isd, ad) in self.down_paths:
            return self.build_fullpaths(self.up_paths, 
                    self.down_paths[(isd, ad)])
        else:
            event = threading.Event()
            self._waiting_targets[(isd, ad)] = event
            self.request_paths(PathInfo.BOTH_PATHS, isd, ad)
            self._waiting_targets[(isd, ad)].wait(SCIONDaemon.TIMEOUT)
            del self._waiting_targets[(isd, ad)]
            if self.up_paths and (isd, ad) in self.down_paths:
                return self.build_fullpaths(self.up_paths,
                    self.down_paths[(isd, ad)])
            else:
                return []

    def update_down_paths(self, isd_ad, pcbs):
        update_dict(self.down_paths, isd_ad, pcbs)
        self.down_paths[isd_ad] = self.down_paths[isd_ad][:PATHS_NO]

#update paths(pcbs...)...
    def handle_path_reply(self, packet):
        print("handle_path_reply()")
        path_reply = PathRecord(packet)
        for pcb in path_reply.pcbs:
            isd = pcb.get_isd()
            ad = pcb.get_last_ad() 
            if self.topology.isd_id != isd or self.topology.ad_id != ad:
                update_dict(self.down_paths, (isd, ad), [pcb], PATHS_NO)
                print("DownPath PATH added:", isd, ad)
            else:
                self.up_paths.append(pcb)
                print("UP PATH added:", isd, ad)

        #wake up sleeping get_paths()
        if (isd, ad) in self._waiting_targets:
            self._waiting_targets[(isd, ad)].set()

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)

        if ptype == PT.PATH_REP:
            self.handle_path_reply(packet)
        else: 
            print("Type %d not supported.", ptype)

    def get_first_hop(self, spkt):
        """
        Returns first hop addr of down-path or end-host addr.
        """
        of = spkt.hdr.path.up_path_hops[0]
        return self.ifid2addr[of.ingress_if]

def main():
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv)!=4:
        print("run: %s IP topo_file conf_file" %sys.argv[0])
        sys.exit()
    sd=SCIONDaemon(IPv4HostAddr(sys.argv[1]), sys.argv[2], sys.argv[3])
    threading.Thread(target=sd.run).start()
    path = sd.get_paths(11, 6)[0]
    dst = IPv4HostAddr("192.168.6.106")
    scion_pkt=SCIONPacket.from_values(sd.addr, dst, b"payload", path)          
    hop = sd.get_first_hop(scion_pkt)
    sd.send(scion_pkt, hop)
    print("Send to: ",hop)
    print(scion_pkt)

if __name__ == "__main__":
    main()
