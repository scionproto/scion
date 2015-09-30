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
:mod:`router_sim` --- SCION edge router(simulator)
==================================================
"""
# Stdlib
import logging

# SCION
from infrastructure.router import Router, IFID_PKT_TOUT
from lib.defines import SCION_UDP_PORT, EXP_TIME_UNIT
from lib.packet.scion import IFIDPayload, PacketType as PT
from lib.util import SCIONTime


class RouterSim(Router):
    """
    Simulator version of the SCION Router
    """
    def __init__(self, router_id, topo_file, config_file, simulator):
        """
        Initialises Router with is_sim set to True.

        :param router_id:
        :type router_id:
        :param topo_file: the topology file name.
        :type topo_file: str
        :param config_file: the configuration file name.
        :type config_file: str
        :param simulator: Instance of simulator class.
        :type simulator: Simulator
        """
        Router.__init__(self, router_id, topo_file, config_file, is_sim=True)
        self.simulator = simulator
        simulator.add_element(str(self.addr.host_addr), self)
        simulator.add_element(str(self.interface.addr), self)

    def send(self, packet, addr, port=SCION_UDP_PORT, use_local_socket=True):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        logging.info("Sending packet to %s from %s", addr, self.addr.host_addr)
        if use_local_socket:
            # SCIONElement.send(self, packet, next_hop.addr, next_hop.port)
            self.simulator.add_event(0., dst=str(addr),
                                     args=(packet.pack(),
                                           (str(self.addr), SCION_UDP_PORT),
                                           (str(addr), port)))
        else:
            self.simulator.add_event(0., dst=str(addr),
                                     args=(packet.pack(),
                                           (str(self.interface.addr),
                                            self.interface.udp_port),
                                           (str(addr), port)))

    def sim_recv(self, packet, src, dst):
        """
        The receive function called when simulator receives a packet
        """
        to_local = False
        if dst[0] == str(self.addr.host_addr) and dst[1] == SCION_UDP_PORT:
            to_local = True
        self.handle_request(packet, src, to_local)

    def run(self):
        self.simulator.add_event(0., cb=self.sync_interface)

    def sync_interface(self):
        """
        Synchronize and initialize the router's interface with that of a
        neighboring router.
        """
        ifid_pld = IFIDPayload.from_values(self.interface.if_id)
        pkt = self._build_packet(PT.BEACON, dst_isd=self.interface.neighbor_isd,
                                 dst_ad=self.interface.neighbor_ad,
                                 payload=ifid_pld)

        self.send(pkt, self.interface.to_addr, self.interface.to_udp_port,
                  False)
        logging.info('Sending IFID_PKT to router: req_id:%d, rep_id:%d',
                     ifid_pld.request_id, ifid_pld.reply_id)

        self.simulator.add_event(IFID_PKT_TOUT, cb=self.sync_interface)

    def clean(self):
        pass

    def verify_of(self, hof, prev_hof, ts):
        """
        Verify freshness of an opaque field.
        We do not check authentication of the MAC(simulator)

        :param hof: the hop opaque field that is verified.
        :type hof: :class:`lib.packet.opaque_field.HopOpaqueField`
        :param prev_hof: previous hop opaque field (according to order of PCB
                         propagation) required for verification.
        :type prev_hof: :class:`lib.packet.opaque_field.HopOpaqueField` or None
        :param ts: timestamp against which the opaque field is verified.
        :type ts: int
        """
        if int(SCIONTime.get_time()) <= ts + hof.exp_time * EXP_TIME_UNIT:
            return True
        else:
            logging.warning("Dropping packet due to expired OF.")
        return False
