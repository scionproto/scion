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
from lib.packet.pcb import HalfPathBeacon, ADMarking, PCBMarking, PeerMarking
from lib.packet.opaque_field import (OpaqueFieldType as OFT, InfoOpaqueField,
    SupportSignatureField, HopOpaqueField, SupportPCBField, SupportPeerField,
    ROTField)
from lib.packet.scion import (SCIONPacket, get_type, Beacon, PathInfo,
    PathRecords, PacketType as PT, PathInfoType as PIT)
from lib.topology_parser import ElementType, NeighborType
from infrastructure.scion_elem import SCIONElement
import threading
import time
import sys
import logging
import copy

#TODO PSz: beacon must be revised. We have design slides for a new format.
class BeaconServer(SCIONElement):
    """
    The SCION Beacon Server.
    """
    DELTA = 24 * 60 * 60 # Amount of real time a PCB packet is valid for.
    TIME_INTERVAL = 4    # SCION second 
    BEACONS_NO = 5

    def __init__(self, addr, topo_file, config_file):
        SCIONElement.__init__(self, addr, topo_file, config_file)
        self.propagated_beacons = []
        self.beacons = [] #TODO replace by pathstore instance
        #TODO: add beacons, up_paths, down_paths

    def propagate_pcb(self, pcb):
        """
        Propagates the beacon to all children.
        """
        assert isinstance(pcb, HalfPathBeacon)
        ingress = pcb.rotf.if_id
        for router_child in self.topology.routers[NeighborType.CHILD]:
            new_pcb = copy.deepcopy(pcb)
            egress = router_child.interface.if_id
            new_pcb.rotf.if_id = egress
            ssf = SupportSignatureField()
            hof = HopOpaqueField.from_values(ingress_if=ingress,
                egress_if=egress)
            spcbf = SupportPCBField.from_values(isd_id=self.topology.isd_id)
            pcbm = PCBMarking.from_values(self.topology.ad_id, ssf, hof, spcbf)
            peer_markings = []
            #TODO PSz: peering link can be only added when there is IfidReply
            #from router
            for router_peer in self.topology.routers[NeighborType.PEER]:
                hof = HopOpaqueField.from_values(ingress_if= \
                    router_peer.interface.if_id, egress_if=egress)
                spf = SupportPeerField.from_values(isd_id=self.topology.isd_id)
                peer_marking = \
                    PeerMarking.from_values(router_peer.interface.neighbor, hof,
                        spf)
                pcbm.ssf.block_size += peer_marking.LEN
                peer_markings.append(peer_marking)
            ad_marking = ADMarking.from_values(pcbm=pcbm, pms=peer_markings)
            new_pcb.add_ad(ad_marking)
            beacon = Beacon.from_values(router_child.addr, new_pcb)
            self.send(beacon, router_child.addr)
            self.propagated_beacons.append(new_pcb)
            logging.info("PCB propagated: %s", new_pcb)

    def handle_pcbs_propagation(self):
        """
        Generates a new beacon or gets ready to forward the one received.
        """
        while True:
            if self.topology.is_core_ad:
                pcb = HalfPathBeacon()
                timestamp = ( ((int(time.time()) + BeaconServer.DELTA) %
                    (BeaconServer.TIME_INTERVAL * 2^16)) /
                    BeaconServer.TIME_INTERVAL)
                pcb.iof = InfoOpaqueField.from_values(info=OFT.TDC_XOVR,
                    timestamp=timestamp, isd_id=self.topology.isd_id)
                pcb.rotf = ROTField()
                self.beacons = [pcb] #CBS does not select beacons
            for pcb in self.beacons:
                self.propagate_pcb(pcb)
            time.sleep(self.config.propagation_time)

    def process_pcb(self, packet):
        """
        Receives beacon and appends it to beacon list.
        """
        if self.topology.is_core_ad:
            logging.error("BEACON received by Core BeaconServer")
            return
        logging.info("PCB received")
        pcb = Beacon(packet).pcb
        self.beacons.append(pcb)
        self.beacons = self.beacons[-BeaconServer.BEACONS_NO:]

    def register_up_path(self, pcb):
        """
        Send Up Path to Local Path Servers
        """
        info = PathInfo.from_values(PIT.UP, self.topology.ad_id,
            self.topology.isd_id)
        dst = self.topology.servers[ElementType.PATH_SERVER].addr
        up_path = PathRecords.from_values(dst, info, [pcb])
        self.send(up_path, dst)

    def register_down_path(self, pcb):
        """
        Send Down Path to Core Path Server
        """
        pcb.remove_signatures()
        info = PathInfo.from_values(PIT.DOWN, self.topology.ad_id,
            self.topology.isd_id)
        core_path = pcb.get_core_path()
        down_path = PathRecords.from_values(self.addr, info, [pcb], core_path)
        next_hop = self.ifid2addr[pcb.rotf.if_id]
        self.send(down_path, next_hop)

    def register_paths(self):
        """
        Registeres paths according to the received beacons.
        """
        if self.topology.is_core_ad or not self.config.registers_paths:
            logging.info("Path registration unwanted, leaving register_paths")
            return

        while True:
            for pcb in self.beacons:
                new_pcb = copy.deepcopy(pcb)
                ingress = new_pcb.rotf.if_id
                egress = 0
                ssf = SupportSignatureField()
                hof = HopOpaqueField.from_values(ingress_if=ingress,
                    egress_if=egress)
                spcbf = SupportPCBField.from_values(isd_id=self.topology.isd_id)
                pcbm = PCBMarking.from_values(self.topology.ad_id, ssf, hof,
                    spcbf)
                peer_markings = []
                #TODO PSz: peering link can be only added when there is
                #IfidReply from router
                for router_peer in self.topology.routers[NeighborType.PEER]:
                    hof = HopOpaqueField.from_values(ingress_if= \
                        router_peer.interface.if_id, egress_if=egress)
                    spf = SupportPeerField.from_values(isd_id= \
                        self.topology.isd_id)
                    peer_marking = \
                        PeerMarking.from_values(router_peer.interface.neighbor,
                            hof, spf)
                    pcbm.ssf.block_size += peer_marking.LEN
                    peer_markings.append(peer_marking)
                ad_marking = ADMarking.from_values(pcbm=pcbm, pms=peer_markings)
                new_pcb.add_ad(ad_marking)
                self.register_up_path(new_pcb)
                self.register_down_path(new_pcb)
                logging.info("Paths registered")
            time.sleep(self.config.registration_time)


    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.IFID_REQ:
            #TODO
            logging.warning("IFID_REQ received, to implement")
        elif ptype == PT.IFID_REP:
            #TODO
            logging.warning("IFID_REP received, to implement")
        elif ptype == PT.BEACON:
            self.process_pcb(packet)
        else:
            logging.warning("Type not supported")
        #TODO add ROT support etc..

    def run(self):
        threading.Thread(target=self.handle_pcbs_propagation).start()
        threading.Thread(target=self.register_paths).start()
        SCIONElement.run(self)


def main():
    """
    Main function.
    """
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 4:
        logging.info("run: %s IP topo_file conf_file", sys.argv[0])
        sys.exit()
    beacon_server = BeaconServer(IPv4HostAddr(sys.argv[1]), sys.argv[2],
        sys.argv[3])
    beacon_server.run()

if __name__ == "__main__":
    main()
