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
from ipaddress import ip_address, ip_network

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


def increment_address(ip_addr, mask, increment=1):
    """
    Increment an IP address value.

    :param ip_addr: the IP address to increment.
    :type ip_addr: str
    :param mask: subnet mask for the given IP address.
    :type mask: str
    :param increment: step the IP address must be incremented of.
    :type increment: int

    :returns: the incremented IP address. It fails if a broadcast address is
              reached.
    :rtype: str
    """
    subnet = ip_network('{}/{}'.format(ip_addr, mask), strict=False)
    ip_addr_obj = ip_address(ip_addr) + increment
    if ip_addr_obj >= subnet.broadcast_address:
        logging.error("Reached a broadcast IP address: " + str(ip_addr_obj))
        sys.exit()
    return str(ip_addr_obj)


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
        src_topo_path = (
            "../../topology/ISD{}/topologies/ISD:{}-AD:{}.json"
            .format(src_isd_ad.isd, src_isd_ad.isd, src_isd_ad.ad)
            )
        dst_topo_path = (
            "../../topology/ISD{}/topologies/ISD:{}-AD:{}.json"
            .format(dst_isd_ad.isd, dst_isd_ad.isd, dst_isd_ad.ad)
            )
        app_start_time = 31.
        app_end_time = 48.
        num_hosts = 10
        ping_interval = 1
        src_host_addr_next = "127.100.100.1"
        dst_host_addr_next = "127.101.100.1"
        ping_apps = list()
        pong_apps = list()
        for host in range(0, num_hosts):
            src_host_addr = haddr_parse("IPv4", src_host_addr_next)
            dst_host_addr = haddr_parse("IPv4", dst_host_addr_next)
            src_host_addr_next = increment_address(src_host_addr_next, 8)
            dst_host_addr_next = increment_address(dst_host_addr_next, 8)
            host1 = SCIONSimHost(src_host_addr, src_topo_path, simulator)
            host2 = SCIONSimHost(dst_host_addr, dst_topo_path, simulator)
            if host == num_hosts - 1:
                ping_interval = 8
            ping_application = SimPingApp(host1, dst_host_addr,
                                          dst_isd_ad.ad, dst_isd_ad.isd,
                                          ping_interval)
            pong_application = SimPongApp(host2)
            ping_apps.append(ping_application)
            pong_apps.append(pong_application)
            ping_application.start(app_start_time)
        simulator.add_event(app_end_time + 0.0001, cb=simulator.terminate)

        event_parser = EventParser(simulator)
        # Add the events into simulator queue
        for event in events:
            event_parser.parse(event)
        simulator.run()

        logging.info("Simulation terminated")
        # start_times = []
        # for time in ping_application.ping_send_time:
        #     start_times.append(time)
        # logging.info("Ping pong status:%s", output)
        total_pings_sent = 0
        total_pings_received = 0
        total_revocations_received = 0
        for ping_app in ping_apps:
            total_pings_sent += ping_app.num_pings_sent
            total_revocations_received += ping_app.revoked_packets
        for pong_app in pong_apps:
            total_pings_received += pong_app.num_pings_received
        print("Number of pings sent ", total_pings_sent)
        print("Number of pings received ", total_pings_received)
        print("Number of revocations received ", total_revocations_received)
        # print("Time of ping pongs ", start_times, len(start_times))


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
