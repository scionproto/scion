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
# SCION
from infrastructure.path_server import CorePathServer, LocalPathServer
from lib.defines import SCION_UDP_PORT


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
