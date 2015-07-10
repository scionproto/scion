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
from lib.defines import TOPOLOGY_PATH

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
    read_sim_file()
    data = read_sim_file()
    init_elements(data, simulator)
    return simulator


def read_sim_file():
    """
    Read sim.conf file

    :returns: data from Simulator conf file
    :rtype: str
    """
    sim_conf_file = os.path.join(TOPOLOGY_PATH, SIM_DIR, SIM_CONF)
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
        if items[0] == "router":
            RouterSim(items[1], items[2], items[3], simulator)
        elif items[0] == "cert_server":
            pass
        elif items[0] == "path_server":
            if items[1] == "core":
                CorePathServerSim(items[2], items[3], items[4], simulator)
            elif items[1] == "local":
                LocalPathServerSim(items[2], items[3], items[4], simulator)
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        elif items[0] == 'beacon_server':
            if items[1] == "core":
                CoreBeaconServerSim(items[2], items[3], items[4], items[5],
                                    simulator)
            elif items[1] == "local":
                LocalBeaconServerSim(items[2], items[3], items[4], items[5],
                                     simulator)
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        else:
            logging.error("Invalid SCIONElement %s", items[0])
            sys.exit()
