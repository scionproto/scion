"""
simulator.py

Copyright 2015 ETH Zurich

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

import logging
import os
import sys

SCRIPTS_DIR = 'topology'
SIM_DIR = 'SIM'
SIM_CONF = 'sim.conf'

def add_element(addr, element):
    """Add an element and its address to simulator""" 
    logging.debug("adding element with addr %s", addr)
    simulator.add_element(addr, element)

def schedule(time, **kwargs):
    """Schedule an event"""
    return simulator.add_event(time, **kwargs)

def unschedule(eid):
    """Unschedule an event"""
    simulator.remove_event(eid)

def stop(time):
    """Stop the simulator"""
    simulator.set_stop_time(time)

def terminate():
    """Terminate the simulator"""
    simulator.terminate()

def run():
    """Start the simulator"""
    simulator.run()

def generate_topology():
    """
    Instantiate all SCION Elements from sim.conf file
    """

    from simulator.beacon_server_sim import CoreBeaconServerSim, LocalBeaconServerSim
    from simulator.cert_server_sim import CertServerSim
    from simulator.lib.sim_core import Simulator
    from simulator.path_server_sim import CorePathServerSim, LocalPathServerSim
    from simulator.router_sim import RouterSim

    global simulator
    simulator = Simulator()

    try:
        sim_conf_file_rel = os.path.join("..", SCRIPTS_DIR, SIM_DIR, SIM_CONF)
        with open(sim_conf_file_rel) as f:
            content = f.read().splitlines()
            f.close()
    except IOError:
        logging.error("Failed to open ../topology/SIM/sim.conf")
        sys.exit()

    for s in content:
        l = s.split()
        if l[0] == "router":
            RouterSim(l[1], l[2], l[3])
        elif l[0] == "cert_server":
            CertServerSim(l[1], l[2], l[3], l[4])
        elif l[0] == "path_server":
            if l[1] == "core":
                CorePathServerSim(l[2], l[3], l[4])
            elif l[1] == "local":
                LocalPathServerSim(l[2], l[3], l[4])
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        elif l[0] == 'beacon_server':
            if l[1] == "core":
                CoreBeaconServerSim(l[2], l[3], l[4], l[5])
            elif l[1] == "local":
                LocalBeaconServerSim(l[2], l[3], l[4], l[5])
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        else:
            logging.error("Invalid SCIONElement %s", l[0])
            sys.exit()
