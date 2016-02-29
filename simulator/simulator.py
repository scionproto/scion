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
:mod:`simulator` --- SCION Simulator
===========================================
"""
# Stdlib
import logging
import os
import sys

# SCION
from lib.defines import GEN_PATH, TOPO_FILE
from lib.packet.scion_addr import ISD_AD
from lib.topology import Topology

# SCION Simulator
from simulator.lib.sim_core import Simulator
from simulator.infrastructure.beacon_server_sim import (
    CoreBeaconServerSim,
    LocalBeaconServerSim
)
from simulator.infrastructure.path_server_sim import (
    CorePathServerSim,
    LocalPathServerSim
)
from simulator.infrastructure.router_sim import RouterSim

SIM_DIR = 'SIM'
SIM_CONF = 'sim.conf'


def init_simulator():
    """
    Initializes the global simulator and creates all the infrastructure

    :returns: The simulator instance
    :rtype: Simulator
    """
    simulator = Simulator()
    data = read_sim_file()
    init_elements(data, simulator)
    return simulator


def read_sim_file():
    """
    Read sim.conf file

    :returns: data from Simulator conf file
    :rtype: str
    """
    sim_conf_file = os.path.join(GEN_PATH, SIM_DIR, SIM_CONF)
    if not os.path.isfile(sim_conf_file):
        logging.error(sim_conf_file + " file missing.")
        sys.exit()
    with open(sim_conf_file) as f:
        content = f.read().splitlines()
        f.close()
    return content


def init_elements(data, simulator):
    """
    Initialize all infrastructure in simulator mode

    :param data: Simulator conf file data
    :type data: str
    :param simulator: Running instance of Simulator
    :type simulator: Simulator
    """
    for line in data:
        items = line.split()
        element = items[0]
        conf_dir = items[1]
        if element.startswith("er"):
            RouterSim(element, conf_dir, simulator)
        elif element.startswith("cs"):
            pass
        elif element.startswith("ps"):
            # Load the topology to see if it is a core/local
            topo = Topology.from_file(os.path.join(conf_dir, TOPO_FILE))
            if topo.is_core_ad:
                CorePathServerSim(element, conf_dir, simulator)
                simulator.core_isd_ads.append(ISD_AD(topo.isd_id,
                                                     topo.ad_id))
            else:
                LocalPathServerSim(element, conf_dir, simulator)
                simulator.local_isd_ads.append(ISD_AD(topo.isd_id,
                                                     topo.ad_id))
        elif element.startswith('bs'):
            # Load the topology to see if it is a core/local
            topo = Topology.from_file(os.path.join(conf_dir, TOPO_FILE))
            if topo.is_core_ad:
                CoreBeaconServerSim(element, conf_dir, simulator)
            else:
                LocalBeaconServerSim(element, conf_dir, simulator)
        else:
            logging.error("Invalid SCIONElement %s", items[0])
            sys.exit()
