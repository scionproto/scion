"""
simulator.py

Copyright 2014 ETH Zurich

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

from lib.sim_core import Simulator

import logging
import sys
import os

SCRIPTS_DIR = 'topology'
SIM_DIR = 'SIM'
SIM_CONF = 'sim.conf'

def add_element (addr, element):
    logging.debug("adding element with addr %s", addr)
    simulator.add_element(addr, element)

def schedule(time, **kwargs):
    return simulator.add_event(time, **kwargs)

def unschedule(eid):
    simulator.remove_event(eid)

def stop(time):
    simulator.set_stop_time(time)

def terminate():
    simulator.terminate()

def run():
    simulator.run()

def generate_topology(topo_str):
    """
    Instantiate all SCION Elements as specified in topo_str

    :param topo_str: Topology Configuration File
    :type topo_str: str

    :returns: dict that maps IP Addresses to SCION Elements
    :rtype: dict
    """

    from ipaddress import IPv4Address
    from simulator.path_server_sim import CorePathServerSim, LocalPathServerSim
    from simulator.beacon_server_sim import CoreBeaconServerSim, LocalBeaconServerSim
    from simulator.router_sim import RouterSim
    from simulator.cert_server_sim import CertServerSim

    global simulator
    simulator = Simulator()

    try:
        sim_conf_file_rel = os.path.join("..", SCRIPTS_DIR, SIM_DIR, SIM_CONF)
        with open(sim_conf_file_rel) as f:
            content = f.read().splitlines()
            f.close()
    except IOError:
        logging.error ("Failed to open ../topology/SIM/sim.conf")
        sys.exit()

    is_sim = True
    for s in content:
        l = s.split()
        if l[0] == "router":
            addr = l[1]
            obj = RouterSim(IPv4Address(l[1]), l[2], l[3])
        elif l[0] == "cert_server":
            addr = l[1]
            obj = CertServerSim(IPv4Address(l[1]), l[2], l[3], l[4])
        elif l[0] == "path_server":
            addr = l[2]
            if l[1] == "core":
                obj = CorePathServerSim(IPv4Address(l[2]), l[3], l[4])
            elif l[1] == "local":
                obj = LocalPathServerSim(IPv4Address(l[2]), l[3], l[4])
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        elif l[0] == 'beacon_server':
            addr = l[2]
            if l[1] == "core":
                obj = CoreBeaconServerSim(IPv4Address(l[2]), l[3], l[4], l[5])
            elif l[1] == "local":
                obj = LocalBeaconServerSim(IPv4Address(l[2]), l[3], l[4], l[5])
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        else:
            logging.error("Invalid SCIONElement %s", l[0])
            sys.exit()
