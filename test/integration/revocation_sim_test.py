#!/usr/bin/python3
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
:mod:`revocation_sim_test` --- Revocation test in Simulator
===========================================================
"""
# Stdlib
import os
import profile
import sys
import logging
import unittest

# SCION
from lib.defines import PROJECT_ROOT
from lib.packet.host_addr import haddr_parse
from lib.packet.scion_addr import ISD_AD

# SCION Simulator
from simulator.application.sim_ping_pong import SimPingApp, SimPongApp
from simulator.lib.event_parser import EventParser
from simulator.endhost.sim_host import SCIONSimHost
from simulator.simulator import init_simulator

SIMULATOR_DIR_NAME = 'simulator'


def read_events_file():
    """
    Format of events file:
    server-name  start/stop  time
    """
    events_file = os.path.join(PROJECT_ROOT, SIMULATOR_DIR_NAME, 'events.conf')
    if not os.path.isfile(events_file):
        logging.error(events_file + " file missing.")
        sys.exit()
    with open(events_file) as f:
        content = f.read().splitlines()
        f.close()
    return content


class RevocationSimTest(unittest.TestCase):
    """
    Unit tests for sim_host.py
    """

    def test(self, events):
        """
        """
        simulator = init_simulator()
        # Setup for ping-pong application
        src_isd_ad = ISD_AD(1, 10)
        dst_isd_ad = ISD_AD(2, 26)
        src_host_addr = haddr_parse("IPV4", "127.1.10.254")
        dst_host_addr = haddr_parse("IPV4", "127.2.26.254")
        src_topo_path = (
            "topology/ISD{}/topologies/ISD:{}-AS:{}.json"
            .format(src_isd_ad.isd, src_isd_ad.isd, src_isd_ad.ad)
            )
        dst_topo_path = (
            "topology/ISD{}/topologies/ISD:{}-AS:{}.json"
            .format(dst_isd_ad.isd, dst_isd_ad.isd, dst_isd_ad.ad)
            )
        host1 = SCIONSimHost(src_host_addr, src_topo_path, simulator)
        host2 = SCIONSimHost(dst_host_addr, dst_topo_path, simulator)
        ping_application = SimPingApp(host1, dst_host_addr,
                                      dst_isd_ad.ad, dst_isd_ad.isd, 4)
        SimPongApp(host2)
        app_start_time = 30.
        ping_application.start(app_start_time)

        event_parser = EventParser(simulator)
        # Add the events into simulator queue
        for event in events:
            event_parser.parse(event)
        simulator.run()

        logging.info("Simulation terminated")
        status_map = {
            0: 'Success',
            1: 'Revocation',
            2: 'Time out',
        }
        output = []
        start_times = []
        for status in ping_application.pong_recv_status:
            output.append(status_map.get(status))
        for time in ping_application.ping_send_time:
            start_times.append(time)
        logging.info("Ping pong status:%s", output)
        logging.info("Time of ping pongs:%s", start_times)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    to_profile = False

    def run_test():
        """
        Calls main function in unit test
        """
        events = read_events_file()
        RevocationSimTest().test(events)
    if to_profile:
        profile.run('run_test()', sort='cumtime')
    else:
        run_test()
