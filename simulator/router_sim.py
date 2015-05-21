# Copyright 2014 ETH Zurich
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
:mod:`router_sim` --- SCION edge router sim
===========================================
"""

import logging
from infrastructure.router import Router, NextHop, IFID_PKT_TOUT
from lib.defines import SCION_UDP_PORT
from ipaddress import IPv4Address
from lib.packet.scion import IFIDPacket
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.simulator import add_element, schedule


class RouterSim(Router):
    """
    Simulator version of the SCION Router
    """
    def __init__(self, addr, topo_file, config_file, pre_ext_handlers=None,
                 post_ext_handlers=None):
        # Constructor of ScionElem
        self._addr = None
        self.topology = None
        self.config = None
        self.ifid2addr = {}
        self.parse_topology(topo_file)
        self.addr = SCIONAddr.from_values(self.topology.isd_id,
                                          self.topology.ad_id, addr)
        if config_file:
            self.parse_config(config_file)
        self.construct_ifid2addr_map()
        add_element(str(self.addr.host_addr), self) 

        # Constructor of Router
        self.interface = None
        for edge_router in self.topology.get_all_edge_routers():
            if edge_router.addr == self.addr.host_addr:
                self.interface = edge_router.interface
                break
        assert self.interface != None
        logging.info("Interface: %s", self.interface.__dict__)

        if pre_ext_handlers:
            self.pre_ext_handlers = pre_ext_handlers
        else:
            self.pre_ext_handlers = {}
        if post_ext_handlers:
            self.post_ext_handlers = post_ext_handlers
        else:
            self.post_ext_handlers = {}
        add_element (str(self.interface.addr), self)

    def send(self, packet, next_hop, use_local_socket=True):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        logging.info("Sending packet to %s", next_hop)
        self.handle_extensions(packet, next_hop, False)
        if use_local_socket:
            # SCIONElement.send(self, packet, next_hop.addr, next_hop.port)
            schedule(0., dst=str(next_hop.addr),
                     args=(packet.pack(),
                           (str(self.addr), SCION_UDP_PORT),
                           (str(next_hop.addr), next_hop.port)))
            
        else:
            schedule(0., dst = str(next_hop.addr),
                     args=(packet.pack(),
                           (str(self.interface.addr), self.interface.udp_port),
                           (str(next_hop.addr), next_hop.port)))

    def sim_recv(self, packet, src, dst):
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        schedule(0., cb=self.simulate_sync_interface)

    def simulate_sync_interface(self):
        """
        Synchronize and initialize the router's interface with that of a
        neighboring router.
        """
        next_hop = NextHop()
        next_hop.addr = self.interface.to_addr
        next_hop.port = self.interface.to_udp_port
        src = SCIONAddr.from_values(self.topology.isd_id, self.topology.ad_id,
                                    self.interface.addr)
        dst_isd_ad = ISD_AD(self.interface.neighbor_isd,
                            self.interface.neighbor_ad)
        ifid_req = IFIDPacket.from_values(src, dst_isd_ad,
                                           self.interface.if_id)

        self.send(ifid_req, next_hop, False)
        logging.info('Sending IFID_PKT to router: req_id:%d, rep_id:%d',
                     ifid_req.request_id, ifid_req.reply_id)

        schedule(IFID_PKT_TOUT, cb=self.simulate_sync_interface)


    def clean(self):
        pass