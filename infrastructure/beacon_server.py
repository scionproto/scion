"""
beaconserver.py

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
from lib.packet.opaque_field import OpaqueFieldType as OFT
from lib.packet.scion import SCIONPacket, IFIDRequest, IFIDReply, get_type,\
        Beacon, PathInfo, PathRequest, PathRecord
from lib.packet.scion import PacketType as PT
from lib.topology import ElementType, NeighborType
from infrastructure.server import ServerBase, SCION_UDP_PORT 
import threading
import time
import socket
import sys
import struct #FIXME remove if Beacon/PCB class is ready
import copy

class BeaconServer(ServerBase):
    """
    The SCION Beacon Server.
    """
    def __init__(self, addr, topo_file, config_file):
        ServerBase.__init__(self, addr, topo_file, config_file)
        self.propagated_beacons = []
        self.beacons = [] #TODO replace by pathstore instance
        # add beacons, up_paths, down_paths

    def add_ad(self, pcb, ingress, egress):
        cert_id = 0
        sig_len = 0
        block_size = 32
        ingress_if = ingress 
        egress_if = egress 
        mac = 0
        isd_id = self.topology.isd_id 
        bwalloc_f = 0
        bwalloc_r = 0
        dyn_bwalloc_f = 0
        dyn_bwalloc_r = 0
        bebw_f = 0
        bebw_r = 0
        ad_id = self.topology.ad_id
        bw_class = 0
        reserved = 0
        sig = b''
        ssf = SupportSignatureField.from_values(cert_id, sig_len, block_size)
        hof = HopField.from_values(ingress_if, egress_if, mac)
        spcbf = SupportPCBField.from_values(isd_id, bwalloc_f, bwalloc_r,
                                            dyn_bwalloc_f, dyn_bwalloc_r,
                                            bebw_f, bebw_r)
        pcbm = PCBMarking.from_values(ad_id, ssf, hof, spcbf)
        ad = AutonomousDomain.from_values(pcbm, [], sig)
        pcb.add_ad(ad)

    def propagate_pcb(self, pcb):
        print ("Before",pcb)
        ingress = pcb.rotf.if_id
        for router in self.topology.routers[NeighborType.CHILD]:
            new_pcb = copy.deepcopy(pcb)
            egress = router.interface.if_id
            new_pcb.rotf.if_id = egress
            self.add_ad(new_pcb, ingress, egress)
            beacon = Beacon.from_values(router.addr, new_pcb)
            self.send(beacon, router.addr)
            self.propagated_beacons.append(new_pcb)
            logging.info("PCB propagated")
            print("print PCB propagated", new_pcb)

    def pcb_propagation(self):
        while True:
            if self.topology.is_core_ad:
                pcb = PCB()
                timestamp = 1010
                hops = 0
                reserved = 0
                pcb.sof = SpecialField.from_values(timestamp,
                        self.topology.isd_id, hops, reserved)
                self.beacons=[pcb] #TODO

            if self.beacons:
                pcb=self.beacons[-1]
                self.propagate_pcb(pcb)
            time.sleep(self.config.propagation_time)

    def process_pcb(self, packet):
        """
        Depending on scenario: a) sends PCB to all beacon servers, or b) to
        neighboring router.
        """
        if self.topology.is_core_ad:
            logging.warning("BEACON received by Core BeaconServer")
            return

        print("PCB received")
        pcb = PCB(packet[16:])#TODO
        self.beacons=[pcb]

    def register_up_path(self, pcb):
        """
        Send Up Path to Local Path Servers
        """
        info = PathInfo.from_values(PathInfo.UP_PATH, self.topology.ad_id,
                self.topology.isd_id)
        dst = self.topology.servers[ElementType.PATH_SERVER].addr
        up_path = PathRecord.from_values(dst, info, pcb) 
        self.send(up_path, dst)

    def register_down_path(self, pcb):
        """
        Send Down Path to Core Path Server
        """
        pcb.remove_sig()
        info = PathInfo.from_values(PathInfo.DOWN_PATH, self.topology.ad_id,
                self.topology.isd_id)
        core_path = pcb.get_core_path()
        down_path = PathRecord.from_values(self.addr, info, pcb, core_path)
        next_hop = self.ifid2addr[pcb.rotf.if_id]
        self.send(down_path, next_hop)

    def path_registration(self):
        if self.topology.is_core_ad or not self.config.registers_paths:
            logging.info("Leaving path_registration()")
            return

        while True:
            if self.beacons:
                pcb = copy.deepcopy(self.beacons[-1])
                ingress = pcb.rotf.if_id
                egress = 0
                self.add_ad(pcb, ingress, egress)
                self.register_up_path(pcb)
                self.register_down_path(pcb)
                logging.info("Paths registered")
            time.sleep(self.config.registration_time)


    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.IFID_REQ:
            print("IFID_REQ received")
        elif ptype == PT.IFID_REP:
            print("IFID_REP received")
        elif ptype==PT.BEACON:
            self.process_pcb(packet)
        else: 
            print("Type not supported")
        #TODO add ROT support etc..

    def run(self):
        threading.Thread(target=self.pcb_propagation).start()
        threading.Thread(target=self.path_registration).start()
        ServerBase.run(self)

def main():
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv)!=4:
        print("run: %s IP topo_file conf_file" %sys.argv[0])
        sys.exit()
    bs=BeaconServer(IPv4HostAddr(sys.argv[1]), sys.argv[2], sys.argv[3])
    bs.run()

if __name__ == "__main__":
    main()
