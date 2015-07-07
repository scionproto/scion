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

SIM_DIR = 'SIM'
SIM_CONF = 'sim.conf'


def add_element(addr, element):
    """
    Add an element along with its IP address to simulator
    The element's sim_recv will be called to send a packet to this address

    :param addr: The address corresponding to element
    :type addr: str
    :param element: The entity which is to be simulated
    :type element:
    """
    logging.debug("adding element with addr %s", addr)
    simulator.add_element(addr, element)


def schedule(time, **kwargs):
    """
    Schedule a Event
    Event can be described either by
    1. Providing a Callback function to be summoned
    2. Specifying the IP address of the Object to be called
        (Implicitly assumes that the Function to be called is sim_recv())

    :param time: relative time that the event would be executed (sec)
    :type time: float
    :param cb: callback function to be executed
    :type cb:
    :type kwargs: arguments as a dictionary
    :param kwargs: dictionary
    :returns: event id
    :rtype: int
    """
    return simulator.add_event(time, **kwargs)


def unschedule(eid):
    """
    Unschedule specfied event

    :param eid: Event id to be removed
    :type eid: int
    """
    simulator.remove_event(eid)


def stop(time):
    """
    Stop the simulator at specfied time

    :param time: Stop time
    :type time: float
    """
    simulator.set_stop_time(time)


def terminate():
    """
    Terminate the simulator
    """
    simulator.terminate()


def run():
    """
    Start the simulator
    """
    simulator.run()


def get_sim_time():
    """
    Get Virtual Time
    """
    return simulator.get_curr_time()


def init_simulator():
    """
    Initializes the global simulator and creates all the infrastructure
    """
    from simulator.lib.sim_core import Simulator

    global simulator
    simulator = Simulator()
    read_sim_file()


def read_sim_file():
    """
    Read sim.conf file
    """
    sim_conf_file = os.path.join(TOPOLOGY_PATH, SIM_DIR, SIM_CONF)
    if not os.path.isfile(sim_conf_file):
        logging.error(sim_conf_file + " file missing.")
        sys.exit()
    with open(sim_conf_file) as f:
        content = f.read().splitlines()
        f.close()
    init_elements(content)


def init_elements(data):
    """
    Initialize all infrastructure in simulator mode

    :param data: Simulator conf file data 
    :type data: str
    """
    from simulator.infrastructure.beacon_server_sim import (
        CoreBeaconServerSim,
        LocalBeaconServerSim
    )
    from simulator.infrastructure.cert_server_sim import CertServerSim
    from simulator.infrastructure.path_server_sim import (
        CorePathServerSim,
        LocalPathServerSim
    )
    from simulator.infrastructure.router_sim import RouterSim
    
    for line in data:
        items = line.split()
        if items[0] == "router":
            RouterSim(items[1], items[2], items[3])
        elif items[0] == "cert_server":
            CertServerSim(items[1], items[2], items[3], items[4])
        elif items[0] == "path_server":
            if items[1] == "core":
                CorePathServerSim(items[2], items[3], items[4])
            elif items[1] == "local":
                LocalPathServerSim(items[2], items[3], items[4])
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        elif items[0] == 'beacon_server':
            if items[1] == "core":
                CoreBeaconServerSim(items[2], items[3], items[4], items[5])
            elif items[1] == "local":
                LocalBeaconServerSim(items[2], items[3], items[4], items[5])
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        else:
            logging.error("Invalid SCIONElement %s", items[0])
            sys.exit()
