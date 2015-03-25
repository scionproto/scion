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

#from lib.packet.host_addr import IPv4HostAddr
#from infrastructure.beacon_server import CoreBeaconServer, LocalBeaconServer
#from infrastructure.cert_server import CertServer
#from infrastructure.path_server import CorePathServer, LocalPathServer
#from infrastructure.router import Router

from lib.sim_core import Simulator

import logging
import sys
import os

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

    from lib.packet.host_addr import IPv4HostAddr
    from infrastructure.beacon_server import CoreBeaconServer, LocalBeaconServer
    from infrastructure.cert_server import CertServer
    from infrastructure.path_server import CorePathServer, LocalPathServer
    from infrastructure.router import Router

    global simulator
    simulator = Simulator()

    try:
        with open("../topology/SIM/sim.conf") as f:
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
            obj = Router(IPv4HostAddr(l[1]), l[2], l[3], is_sim=is_sim)
        elif l[0] == "cert_server":
            addr = l[1]
            obj = CertServer(IPv4HostAddr(l[1]), l[2], l[3], l[4], is_sim)
        elif l[0] == "path_server":
            addr = l[2]
            if l[1] == "core":
                obj = CorePathServer(IPv4HostAddr(l[2]), l[3], l[4], is_sim)
            elif l[1] == "local":
                obj = LocalPathServer(IPv4HostAddr(l[2]), l[3], l[4], is_sim)
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        elif l[0] == 'beacon_server':
            addr = l[2]
            if l[1] == "core":
                obj = CoreBeaconServer(IPv4HostAddr(l[2]), l[3], l[4], l[5], is_sim)
            elif l[1] == "local":
                obj = LocalBeaconServer(IPv4HostAddr(l[2]), l[3], l[4], l[5], is_sim)
            else:
                logging.error("First parameter can only be 'local' or 'core'!")
                sys.exit()
        else:
            logging.error("Invalid SCIONElement %s", l[0])
            sys.exit()
