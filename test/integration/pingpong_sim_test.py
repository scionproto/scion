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
:mod:`pingpong_sim_test` --- PingPong test in Simulator
=======================================================
"""
# Stdlib
import logging
import profile
import unittest
from ipaddress import IPv4Address

# SCION
from lib.packet.scion_addr import ISD_AD

# SCION Simulator
from simulator.application.sim_ping_pong import SimPingApp, SimPongApp
from simulator.endhost.sim_host import SCIONSimHost
from simulator.simulator import init_simulator


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
        simulator = init_simulator()
        src_isd_ad = ISD_AD(1, 10)
        dst_isd_ad = ISD_AD(2, 26)
        src_host_addr = IPv4Address("127.1.10.254")
        dst_host_addr = IPv4Address("127.2.26.254")
        src_topo_path = (
            "../../topology/ISD{}/topologies/ISD:{}-AD:{}.json"
            .format(src_isd_ad.isd, src_isd_ad.isd, src_isd_ad.ad)
            )
        dst_topo_path = (
            "../../topology/ISD{}/topologies/ISD:{}-AD:{}.json"
            .format(dst_isd_ad.isd, dst_isd_ad.isd, dst_isd_ad.ad)
            )
        host1 = SCIONSimHost(src_host_addr, src_topo_path, simulator)
        host2 = SCIONSimHost(dst_host_addr, dst_topo_path, simulator)
        ping_application = SimPingApp(host1, dst_host_addr,
                                      dst_isd_ad.ad, dst_isd_ad.isd)
        pong_application = SimPongApp(host2)
        app_start_time = 40.
        ping_application.start(app_start_time)
        simulator.run()
        logging.info("Simulation terminated")
        assert ping_application.pong_received and pong_application.ping_received

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    to_profile = False

    def run_test():
        """
        Calls main function in unit test
        """
        unittest.main()
    if to_profile:
        profile.run('run_test()', sort='cumtime')
    else:
        run_test()
