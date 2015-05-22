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
:mod:`path_server_sim` --- SCION path server sim
========================================
"""

from _collections import defaultdict
from external.expiring_dict import ExpiringDict
from infrastructure.path_server import CorePathServer, LocalPathServer
from lib.defines import SCION_UDP_PORT
from lib.packet.scion_addr import SCIONAddr
from lib.path_db import PathSegmentDB
from lib.simulator import add_element, schedule

class CorePathServerSim(CorePathServer):
    """
    Simulator version of SCION Path Server in a core AD
    """
    def __init__(self, addr, topo_file, config_file):
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

        self.down_segments = PathSegmentDB()
        self.core_segments = PathSegmentDB()  # Direction of the propagation.
        self.pending_down = {}  # Dict of pending DOWN _and_ UP_DOWN requests.
        self.pending_core = {}
        self.waiting_targets = set()  # Used when local PS doesn't have up-path.
        # TODO replace by some cache data struct. (expiringdict ?)
        self.revocations = ExpiringDict(1000, 300)

        # Sanity check that we should indeed be a core path server.
        assert self.topology.is_core_ad, "This shouldn't be a core PS!"

        self.leases = self.LeasesDict()
        self.iftoken2seg = defaultdict(set)
        self.core_ads = set()

        # Init core ads set.
        for router in self.topology.routing_edge_routers:
            self.core_ads.add((router.interface.neighbor_isd,
                               router.interface.neighbor_ad))

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        schedule(0., dst=str(dst),
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
    Simulator version of SCION Path Server in a local AD
    """
    def __init__(self, addr, topo_file, config_file):
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

        self.down_segments = PathSegmentDB()
        self.core_segments = PathSegmentDB()  # Direction of the propagation.
        self.pending_down = {}  # Dict of pending DOWN _and_ UP_DOWN requests.
        self.pending_core = {}
        self.waiting_targets = set()  # Used when local PS doesn't have up-path.
        # TODO replace by some cache data struct. (expiringdict ?)
        self.revocations = ExpiringDict(1000, 300)
        
        # Sanity check that we should indeed be a local path server.
        assert not self.topology.is_core_ad, "This shouldn't be a local PS!"
        # Database of up-segments to the core.
        self.up_segments = PathSegmentDB()
        self.pending_up = []  # List of pending UP requests.

    def send(self, packet, dst, dst_port=SCION_UDP_PORT):
        """
        Send *packet* to *dst* (to port *dst_port*).
        """
        schedule(0., dst=str(dst),
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
