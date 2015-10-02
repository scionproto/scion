# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`path_server_sim` --- SCION path server(simulator)
=======================================================
"""
# Stdlib
import copy
import logging

# SCION
from infrastructure.path_server import CorePathServer, LocalPathServer
from lib.defines import SCION_UDP_PORT
from lib.packet.scion import PacketType as PT
from lib.path_db import DBResult


class CorePathServerSim(CorePathServer):
    """
    Simulator version of the SCION Path Server in a core AD
    """
    def __init__(self, server_id, topo_file, config_file, simulator):
        """
        Initialises CorePathServer with is_sim set to True.

        :param server_id:
        :type server_id:
        :param topo_file:
        :type topo_file:
        :param config_file:
        :type config_file:
        :param simulator: Instance of simulator class
        :type simulator: Simulator
        """
        CorePathServer.__init__(self, server_id, topo_file, config_file,
                                is_sim=True)
        self.simulator = simulator
        simulator.add_element(str(self.addr.host_addr), self)

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        self.simulator.add_event(0., dst=str(dst),
                                 args=(packet.pack(),
                                       (str(self.addr), SCION_UDP_PORT),
                                       (str(dst), dst_port)))

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet
        """
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        pass

    def clean(self):
        pass

    def _handle_core_segment_record(self, pkt, from_zk=False):
        """
        Handle registration of a core path. Removing zookeeper related calls.
        """
        records = pkt.get_payload()
        if not records.pcbs:
            return
        for pcb in records.pcbs:
            dst_ad = pcb.get_first_pcbm().ad_id
            dst_isd = pcb.get_first_pcbm().isd_id
            src_ad = pcb.get_last_pcbm().ad_id
            src_isd = pcb.get_last_pcbm().isd_id
            res = self.core_segments.update(pcb, first_isd=dst_isd,
                                            first_ad=dst_ad, last_isd=src_isd,
                                            last_ad=src_ad)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
                logging.info("Core-Path registered: (%d, %d) -> (%d, %d), "
                             "from_zk: %s", src_isd, src_ad, dst_isd, dst_ad,
                             from_zk)
            else:
                logging.info("Core-Path already known: (%d, %d) -> (%d, %d), "
                             "from_zk: %s", src_isd, src_ad, dst_isd, dst_ad,
                             from_zk)
            if dst_isd == self.topology.isd_id:
                self.core_ads.add((dst_isd, dst_ad))
        if not from_zk:
            pass
        # Send pending requests that couldn't be processed due to the lack of
        # a core path to the destination PS.
        if self.waiting_targets:
            pcb = records.pcbs[0]
            next_hop = self.ifid2addr[pcb.get_last_pcbm().hof.ingress_if]
            path = pcb.get_path(reverse_direction=True)
            targets = copy.copy(self.waiting_targets)
            for (target_isd, target_ad, seg_info) in targets:
                if target_isd == dst_isd:
                    req_pkt = self._build_packet(
                        PT.PATH_MGMT, payload=seg_info, path=path,
                        dst_isd=dst_isd, dst_ad=dst_ad)
                    self.send(req_pkt, next_hop)
                    self.waiting_targets.remove((target_isd, target_ad,
                                                 seg_info))
                    logging.debug("Sending path request %s on newly learned "
                                  "path to (%d, %d)", seg_info, dst_isd, dst_ad)
        # Serve pending core path requests.
        for target in [((src_isd, src_ad), (dst_isd, dst_ad)),
                       ((src_isd, src_ad), (dst_isd, 0))]:
            if self.pending_core:
                logging.debug("D01 Target: %s, pending_core: %s " % (target,
                              self.pending_core))
            if target in self.pending_core:
                segments_to_send = self.core_segments(first_isd=dst_isd,
                                                      first_ad=dst_ad or None,
                                                      last_isd=src_isd,
                                                      last_ad=src_ad)
                segments_to_send = segments_to_send[:self.MAX_SEG_NO]
                for pkt in self.pending_core[target]:
                    self.send_path_segments(pkt, segments_to_send)
                del self.pending_core[target]
                logging.debug("D02: %s removed from pending_core", target)


class LocalPathServerSim(LocalPathServer):
    """
    Simulator version of the SCION Path Server in a local AD
    """
    def __init__(self, server_id, topo_file, config_file, simulator):
        """
        Initialises LocalPathServer with is_sim set to True.

        :param server_id:
        :type server_id:
        :param topo_file:
        :type topo_file:
        :param config_file:
        :type config_file:
        :param simulator: Instance of simulator class
        :type simulator: Simulator
        """
        LocalPathServer.__init__(self, server_id, topo_file, config_file,
                                 is_sim=True)
        self.simulator = simulator
        simulator.add_element(str(self.addr.host_addr), self)

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        self.simulator.add_event(0., dst=str(dst),
                                 args=(packet.pack(),
                                       (str(self.addr), SCION_UDP_PORT),
                                       (str(dst), dst_port)))

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet
        """
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        pass

    def clean(self):
        pass

    def _handle_up_segment_record(self, pkt, from_zk=False):
        """
        Handle Up Path registration from local BS or ZK's cache.
        Removing zookeeper related calls.

        :param pkt:
        :type pkt:
        """
        records = pkt.get_payload()
        if not records.pcbs:
            return
        for pcb in records.pcbs:
            res = self.up_segments.update(pcb, pcb.get_first_pcbm().isd_id,
                                          pcb.get_first_pcbm().ad_id,
                                          self.topology.isd_id,
                                          self.topology.ad_id)
            if res == DBResult.ENTRY_ADDED:
                self._add_if_mappings(pcb)
                logging.info("Up-Segment to (%d, %d) registered, from_zk: %s.",
                             pcb.get_first_pcbm().isd_id,
                             pcb.get_first_pcbm().ad_id, from_zk)
        if not from_zk:
            pass
        # Sending pending targets to the core using first registered up-path.
        if self.waiting_targets:
            pcb = records.pcbs[0]
            path = pcb.get_path(reverse_direction=True)
            dst_isd = pcb.get_isd()
            dst_ad = pcb.get_first_pcbm().ad_id
            next_hop = self.ifid2addr[path.get_fwd_if()]
            targets = copy.copy(self.waiting_targets)
            for (isd, ad, seg_info) in targets:
                req_pkt = self._build_packet(
                    PT.PATH_MGMT, dst_isd=dst_isd, dst_ad=dst_ad,
                    path=path, payload=seg_info)
                self.send(req_pkt, next_hop)
                logging.info("PATH_REQ sent using (first) registered up-path")
                self.waiting_targets.remove((isd, ad, seg_info))
        # Handling pending UP_PATH requests.
        for path_request in self.pending_up:
            self.send_path_segments(path_request,
                                    self.up_segments()[:self.MAX_SEG_NO])
        self.pending_up = []
