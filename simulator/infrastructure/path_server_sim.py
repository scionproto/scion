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
from infrastructure.path_server.core import CorePathServer
from infrastructure.path_server.local import LocalPathServer
from lib.defines import SCION_UDP_PORT


class CorePathServerSim(CorePathServer):
    """
    Simulator version of the SCION Path Server in a core AD
    """
    def __init__(self, server_id, conf_dir, simulator):
        """
        Initialises CorePathServer with is_sim set to True.

        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param Simulator simulator: Instance of simulator class.
        """
        CorePathServer.__init__(self, server_id, conf_dir, is_sim=True)
        self.simulator = simulator
        simulator.add_element(str(self.addr.host_addr), self)
        simulator.add_name(server_id, str(self.addr.host_addr))
        self.num_revocation_msgs = 0

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

    def _share_segments(self, pkt):
        """
        Share path segments (via ZK) with other path servers.
        No zookeeper in simulation.
        """
        pass

    def _send_to_master(self, pkt):
        """
        Send 'pkt' to a master. No zookeeper in simulation.
        """
        pass


class LocalPathServerSim(LocalPathServer):
    """
    Simulator version of the SCION Path Server in a local AD
    """
    def __init__(self, server_id, conf_dir, simulator):
        """
        Initialises LocalPathServer with is_sim set to True.

        :param str server_id: server identifier.
        :param str conf_dir: configuration directory.
        :param Simulator simulator: Instance of simulator class.
        """
        LocalPathServer.__init__(self, server_id, conf_dir, is_sim=True)
        self.simulator = simulator
        simulator.add_element(str(self.addr.host_addr), self)
        simulator.add_name(server_id, str(self.addr.host_addr))
        self.num_revocation_msgs = 0

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

    def _share_segments(self, pkt):
        """
        Share path segments (via ZK) with other path servers.
        No zookeeper in simulation
        """
        pass
