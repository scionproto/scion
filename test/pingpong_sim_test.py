"""
pingpong_sim_test.py

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

from application.sim_ping_pong import SimPingApp, SimPongApp
from endhost.sim_host import SCIONSimHost
from ipaddress import IPv4Address
from lib.simulator import generate_topology, stop, run

import unittest
import logging
import sys
import os
import profile

class PingPongSimTest(unittest.TestCase):
    """
    Unit tests for sim_host.py
    """

    def test(self):
        """
        Testing function. This verifies the simulation implementation for 
        end-2-end data communication using PingPong Application.

        Creates two end-hosts---Sender is 127.1.10.254 in ISD:1 AD:10,
        and Receiver is 127.2.26.254 in ISD:2 AD:26
            
        """
        generate_topology("../SIM/sim.conf")

        h1 = SCIONSimHost(IPv4Address("127.1.10.254"), "../topology/ISD1/topologies/ISD:1-AD:10.json")
        h2 = SCIONSimHost(IPv4Address("127.2.26.254"), "../topology/ISD2/topologies/ISD:2-AD:26.json")

        pi = SimPingApp(h1, IPv4Address("127.2.26.254"), 26, 2)
        po = SimPongApp(h2)

        app_start_time = 20.
        pi.start(app_start_time)

        run()
        logging.info("Simulation terminated")
        assert (pi.pong_received and po.ping_received)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    # def RunMe():
    #     unittest.main()
    # profile.run('RunMe()',sort='ncalls')
    unittest.main()
