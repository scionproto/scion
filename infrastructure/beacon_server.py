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

from _collections import deque
import copy
from infrastructure.scion_elem import SCIONElement
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.opaque_field import (OpaqueFieldType as OFT, InfoOpaqueField,
    SupportSignatureField, HopOpaqueField, SupportPCBField, SupportPeerField,
    ROTField)
from lib.packet.pcb import (PathSegment, ADMarking, PCBMarking, PeerMarking,
    PathConstructionBeacon, PathSegmentInfo, PathSegmentRecords,
    PathSegmentType as PST)
from lib.packet.scion import SCIONPacket, get_type, PacketType as PT
import logging
import sys
import threading
import time


# TODO PSz: beacon must be revised. We have design slides for a new format.
class BeaconServer(SCIONElement):
    """
    The SCION PathConstructionBeacon Server.

    Attributes:
        beacons: A FIFO queue containing the beacons for processing and
            propagation.
        reg_queue: A FIFO queue containing paths for registration with path
            servers.
    """
    DELTA = 24 * 60 * 60  # Amount of real time a PCB packet is valid for.
    TIME_INTERVAL = 4  # SCION second
    BEACONS_NO = 5

    def __init__(self, addr, topo_file, config_file):
        SCIONElement.__init__(self, addr, topo_file, config_file)
        # TODO: Do we need to keep track of propagated beacons? If yes we should
        # also clear the list from time to time.
        # self.propagated_beacons = []
        self.beacons = deque()
        self.reg_queue = deque()
        # TODO: add beacons, up_paths, down_paths

    def propagate_downstream_pcb(self, pcb):
        """
        Propagates the beacon to all children.
        """
        assert isinstance(pcb, PathSegment)
        ingress_if = pcb.rotf.if_id
        for router_child in self.topology.child_edge_routers:
            new_pcb = copy.deepcopy(pcb)
            egress_if = router_child.interface.if_id
            new_pcb.rotf.if_id = egress_if
            ad_marking = self._create_ad_marking(ingress_if, egress_if)
            new_pcb.add_ad(ad_marking)
            beacon = PathConstructionBeacon.from_values(router_child.addr,
                                                        new_pcb)
            self.send(beacon, router_child.addr)
            # logging.info("PCB propagated: %s", new_pcb)
            logging.info("Downstream PCB propagated!")

    def handle_pcbs_propagation(self):
        """
        Main loop to propagate received beacons.
        """
        while True:
            while self.beacons:
                pcb = self.beacons.popleft()
                self.propagate_downstream_pcb(pcb)
                self.reg_queue.append(pcb)
            time.sleep(self.config.propagation_time)

    def process_pcb(self, beacon):
        """
        Receives beacon and appends it to beacon list.
        """
        assert isinstance(beacon, PathConstructionBeacon)
        logging.info("PCB received")
        self.beacons.append(beacon.pcb)
        # self.beacons = self.beacons[-BeaconServer.BEACONS_NO:]

    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        pass

    def _create_ad_marking(self, ingress_if, egress_if):
        """
        Creates an AD Marking with the given ingress and egress interfaces.
        """
        ssf = SupportSignatureField()
        hof = HopOpaqueField.from_values(ingress_if, egress_if)
        spcbf = SupportPCBField.from_values(isd_id=self.topology.isd_id)
        pcbm = PCBMarking.from_values(self.topology.ad_id, ssf, hof,
                                      spcbf)
        peer_markings = []
        # TODO PSz: peering link can be only added when there is
        # IfidReply from router
        for router_peer in self.topology.peer_edge_routers:
            hof = HopOpaqueField.from_values(router_peer.interface.if_id,
                                             egress_if)
            spf = SupportPeerField.from_values(self.topology.isd_id)
            peer_marking = \
                PeerMarking.from_values(router_peer.interface.neighbor_ad,
                                        hof, spf)
            pcbm.ssf.block_size += peer_marking.LEN
            peer_markings.append(peer_marking)

        return ADMarking.from_values(pcbm, peer_markings)

    def handle_request(self, packet, sender, from_local_socket=True):
        """
        Main routine to handle incoming SCION packets.
        """
        spkt = SCIONPacket(packet)
        ptype = get_type(spkt)
        if ptype == PT.IFID_REQ:
            # TODO
            logging.warning("IFID_REQ received, to implement")
        elif ptype == PT.IFID_REP:
            # TODO
            logging.warning("IFID_REP received, to implement")
        elif ptype == PT.BEACON:
            self.process_pcb(PathConstructionBeacon(packet))
        else:
            logging.warning("Type not supported")
        # TODO add ROT support etc..

    def run(self):
        threading.Thread(target=self.handle_pcbs_propagation).start()
        threading.Thread(target=self.register_segments).start()
        SCIONElement.run(self)


class CoreBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a core AD.

    Starts broadcasting beacons down-stream within an ISD and across ISDs
    towards other core beacon servers.
    """
    def __init__(self, addr, topo_file, config_file):
        BeaconServer.__init__(self, addr, topo_file, config_file)
        # Sanity check that we should indeed be a core beacon server.
        assert self.topology.is_core_ad, "This shouldn't be a core BS!"

    def propagate_core_pcb(self, pcb):
        """
        Propagates the core beacons to other core ADs.
        """
        assert isinstance(pcb, PathSegment)
        ingress_if = pcb.rotf.if_id
        for core_router in self.topology.routing_edge_routers:
            new_pcb = copy.deepcopy(pcb)
            egress_if = core_router.interface.if_id
            new_pcb.rotf.if_id = egress_if
            ad_marking = self._create_ad_marking(ingress_if, egress_if)
            new_pcb.add_ad(ad_marking)
            beacon = PathConstructionBeacon.from_values(core_router.addr,
                                                        new_pcb)
            self.send(beacon, core_router.addr)
            # self.propagated_beacons.append(new_pcb)
            logging.info("Core PCB propagated!")

    def handle_pcbs_propagation(self):
        """
        Generates a new beacon or gets ready to forward the one received.
        """
        while True:
            # Create beacon for downstream ADs.
            downstream_pcb = PathSegment()
            timestamp = (((int(time.time()) + BeaconServer.DELTA) %
                          (BeaconServer.TIME_INTERVAL * (2 ** 16))) /
                         BeaconServer.TIME_INTERVAL)
            downstream_pcb.iof = InfoOpaqueField.from_values(OFT.TDC_XOVR,
                False, timestamp, self.topology.isd_id)
            downstream_pcb.rotf = ROTField()
            self.propagate_downstream_pcb(downstream_pcb)

            # Create beacon for core ADs.
            core_pcb = PathSegment()
            core_pcb.iof = InfoOpaqueField.from_values(OFT.TDC_XOVR, False,
                                                       timestamp,
                                                       self.topology.isd_id)
            core_pcb.rotf = ROTField()
            self.propagate_core_pcb(core_pcb)

            # Propagate received beacons. A core beacon server can only receive
            # beacons from other core beacon servers.
            while self.beacons:
                pcb = self.beacons.popleft()
                self.propagate_core_pcb(pcb)
                self.reg_queue.append(pcb)
            time.sleep(self.config.propagation_time)

    def register_segments(self):
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, leaving"
                         "register_segments")
            return

        while True:
            while self.reg_queue:
                pcb = self.reg_queue.popleft()
                new_pcb = copy.deepcopy(pcb)
                ad_marking = self._create_ad_marking(new_pcb.rotf.if_id, 0)
                new_pcb.add_ad(ad_marking)
                self.register_core_segment(new_pcb)
                logging.info("Paths registered")
            time.sleep(self.config.registration_time)

    def register_core_segment(self, pcb):
        """
        Registers the core segment contained in 'pcb' with the local core path
        server and the originating core path server.
        """
        info = PathSegmentInfo.from_values(PST.CORE,
                                           pcb.get_first_ad().spcbf.isd_id,
                                           self.topology.isd_id,
                                           pcb.get_first_ad().ad_id,
                                           self.topology.ad_id)
        # Register core path with local core path server.
        if self.topology.path_servers != []:
            # TODO: pick other than the first path server
            dst = self.topology.path_servers[0].addr
            path_rec = PathSegmentRecords.from_values(dst, info, [pcb])
            logging.debug("Registering core path with local PS.")
            self.send(path_rec, dst)

        # Register core path with originating core path server.
        pcb.remove_signatures()
        path = pcb.get_path(reverse_direction=True)
        path_rec = PathSegmentRecords.from_values(self.addr, info, [pcb], path)
        if_id = path.get_first_hop_of().ingress_if
        next_hop = self.ifid2addr[if_id]
        logging.debug("Registering core path with originating PS.")
        self.send(path_rec, next_hop)

    def process_pcb(self, beacon):
        assert isinstance(beacon, PathConstructionBeacon)
        logging.info("PCB received")
        pcb = beacon.pcb
        # Before we append the PCB for further processing we need to check that
        # it hasn't been received before.
        for ad in pcb.ads:
            isd_id = ad.pcbm.spcbf.isd_id
            ad_id = ad.pcbm.ad_id
            if (isd_id == self.topology.isd_id and
                ad_id == self.topology.ad_id):
                logging.debug("Core Segment PCB already seen. Dropping...")
                return
        self.beacons.append(pcb)


class LocalBeaconServer(BeaconServer):
    """
    PathConstructionBeacon Server in a non-core AD.

    Receives, processes, and propagates beacons received by other beacon
    servers.
    """
    def __init__(self, addr, topo_file, config_file):
        BeaconServer.__init__(self, addr, topo_file, config_file)
        # Sanity check that we should indeed be a local beacon server.
        assert not self.topology.is_core_ad, "This shouldn't be a local BS!"

    def register_up_segment(self, pcb):
        """
        Send up-segment to Local Path Servers
        """
        info = PathSegmentInfo.from_values(PST.UP,
                                           self.topology.isd_id,
                                           self.topology.isd_id,
                                           pcb.get_first_ad().ad_id,
                                           self.topology.ad_id)
        # TODO: pick other than the first path server
        dst = self.topology.path_servers[0].addr
        up_path = PathSegmentRecords.from_values(dst, info, [pcb])
        self.send(up_path, dst)

    def register_down_segment(self, pcb):
        """
        Send down-segment to Core Path Server
        """
        pcb.remove_signatures()
        info = PathSegmentInfo.from_values(PST.DOWN,
                                           self.topology.isd_id,
                                           self.topology.isd_id,
                                           pcb.get_first_ad().ad_id,
                                           self.topology.ad_id)
        core_path = pcb.get_path(reverse_direction=True)
        down_path = PathSegmentRecords.from_values(self.addr, info, [pcb],
                                                   core_path)
        if_id = core_path.get_first_hop_of().ingress_if
        next_hop = self.ifid2addr[if_id]
        self.send(down_path, next_hop)

    def register_segments(self):
        """
        Registers paths according to the received beacons.
        """
        if not self.config.registers_paths:
            logging.info("Path registration unwanted, "
                         "leaving register_segments")
            return

        while True:
            while self.reg_queue:
                pcb = self.reg_queue.popleft()
                new_pcb = copy.deepcopy(pcb)
                ad_marking = self._create_ad_marking(new_pcb.rotf.if_id, 0)
                new_pcb.add_ad(ad_marking)
                self.register_up_segment(new_pcb)
                self.register_down_segment(new_pcb)
                logging.info("Paths registered")
            time.sleep(self.config.registration_time)


def main():
    """
    Main function.
    """
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) != 5:
        logging.info("run: %s <core|local> IP topo_file conf_file", sys.argv[0])
        sys.exit()

    if sys.argv[1] == "core":
        beacon_server = CoreBeaconServer(IPv4HostAddr(sys.argv[2]), sys.argv[3],
                                         sys.argv[4])
    elif sys.argv[1] == "local":
        beacon_server = LocalBeaconServer(IPv4HostAddr(sys.argv[2]),
                                          sys.argv[3],
                                          sys.argv[4])
    else:
        logging.error("First parameter can only be 'local' or 'core'!")
        sys.exit()
    beacon_server.run()

if __name__ == "__main__":
    main()
