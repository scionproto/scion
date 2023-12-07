#!/usr/bin/env python3

# Copyright 2023 SCION Association
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


import shutil
import time

from collections import namedtuple
from plumbum import cli
from plumbum.cmd import docker, whoami
from plumbum import cmd

from acceptance.common import base

import logging
import json
from http.client import HTTPConnection
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# Those values are valid expectations only when running in the CI environment.
TEST_CASES = {
    'in': 270000,
    'out': 240000,
    'in_transit': 270000,
    'out_transit': 240000,
    'br_transit': 260000,
}


def sudo(*args: [str]) -> str:
    # -A, --askpass makes sure command is failing and does not wait for
    # interactive password input.
    return cmd.sudo("-A", *args)


# Convenience types to carry interface params.
IntfReq = namedtuple("IntfReq", "label, prefixLen, ip, peerIp")
Intf = namedtuple("Intf", "name, mac, peerMac")


# Make-up an eth mac address as unique as the given IP.
# Assumes ips in a /16 or smaller block (i.e. The last two bytes are unique within the test).
def mac_for_ip(ip: str) -> str:
    ipBytes = ip.split(".")
    return 'f0:0d:ca:fe:{:02x}:{:02x}'.format(int(ipBytes[2]), int(ipBytes[3]))


class RouterBMTest(base.TestBase):
    """
    Tests that the implementation of a router has sufficient performance in terms of packets
    per available machine*second (i.e. one accumulated second of all configured CPUs available
    to execute the router code).

    This test runs and execute a single router. The outgoing packets are not observed, the incoming
    packets are fed directly by the test driver. The other routers in the topology are a fiction,
    they exist only in the routers configuration.

    The topology (./conf/topology.json) is the following:

    AS2 (br2) ---+== (br1a) AS1 (br1b) ---- (br4) AS4
                 |
    AS3 (br3) ---+

    Only br1 is executed and observed.

    Pretend traffic is injected by brload's. See the test cases for details.
    """

    ci = cli.Flag(
        "ci",
        help="Do extra checks for CI",
        envname="CI"
    )

    def create_interface(self, req: IntfReq, ns: str):
        """
        Creates a pair of virtual interfaces, with one end in the given network namespace and the
        other in the host stack.

        The outcome is the pair of interfaces and a record in intfMap, which associates the given
        label with the network interface's host-side name and two mac addresses; one for each end
        of the pair. The mac addresses, if they can be chosen, are not chosen by the invoker, but
        by this function.

        We could add:
          sudo("ip", "addr", "add", f"{req.peerIp}/{req.prefixLen}", "dev", hostIntf)
          sudo("ip", "link", "set", hostIntf, "address", peerMac)
        But it not necessary. The ARP seeding on the other end is enough. By not setting these
        addresses on the host side we make it look a little weird for anyone who would look at it
        but we avoid the risk of colliding with actual addresses of the host.

        Args:
          IntfReq: A requested router-side network interface. It comprises:
                   * A label by which brload indetifies that interface.
                   * The IP address to be assigned to that interface.
                   * The IP address of one neighbor.
          ns: The network namespace where that interface must exist.

        """

        hostIntf = f"veth_{req.label}_host"
        brIntf = f"veth_{req.label}"
        peerMac = mac_for_ip(req.peerIp)
        mac = mac_for_ip(req.ip)

        # The interfaces
        sudo("ip", "link", "add", hostIntf, "type", "veth", "peer", "name", brIntf)
        sudo("ip", "link", "set", hostIntf, "mtu", "8000")
        sudo("ip", "link", "set", brIntf, "mtu", "8000")
        sudo("sysctl", "-qw", f"net.ipv6.conf.{hostIntf}.disable_ipv6=1")
        sudo("ethtool", "-K", brIntf, "rx", "off", "tx", "off")
        sudo("ip", "link", "set", brIntf, "address", mac)

        # The network namespace
        sudo("ip", "link", "set", brIntf, "netns", ns)

        # The addresses (presumably must be done once the br interface is in the namespace).
        sudo("ip", "netns", "exec", ns,
             "ip", "addr", "add", f"{req.ip}/{req.prefixLen}", "dev", brIntf)
        sudo("ip", "netns", "exec", ns,
             "ip", "neigh", "add", req.peerIp, "lladdr", peerMac, "nud", "permanent",
             "dev", brIntf)
        sudo("ip", "netns", "exec", ns,
             "sysctl", "-qw", f"net.ipv6.conf.{brIntf}.disable_ipv6=1")

        # Fit for duty.
        sudo("ip", "link", "set", hostIntf, "up")
        sudo("ip", "netns", "exec", ns,
             "ip", "link", "set", brIntf, "up")

        self.intfMap[req.label] = Intf(hostIntf, mac, peerMac)

    def setup_prepare(self):
        super().setup_prepare()

        # get the config where the router can find it.
        shutil.copytree("acceptance/router_benchmark/conf/", self.artifacts / "conf")

        # We need a custom network so can create veth interfaces of our own chosing.
        docker("network", "create",  "-d", "bridge", "benchmark")

        # This test is useless without prometheus. Also, we need a running container to have
        # a usable network namespace that we can configure before the router runs. So, start
        # prometheus now and then have the router share the same network stack.

        # FWIW, the alternative would be to start the router's container without the router,
        # configure the interfaces, and then start the router. We'd still need prometheus, though,
        # and we'd need to expose the router's metrics port to prometheus in some way. So, this is
        # simpler.
        docker("run",
               "-v", f"{self.artifacts}/conf:/share/conf",
               "-d",
               "--network", "benchmark",
               "--publish", "9999:9090",
               "--name", "prometheus",
               "prom/prometheus:v2.47.2",
               "--config.file", "/share/conf/prometheus.yml")

        # Link that namespace to where the ip commands expect it. While at it give it a simple name.
        sudo("mkdir", "-p", "/var/run/netns")
        ns = docker("inspect",
                    "prometheus",
                    "-f", "{{.NetworkSettings.SandboxKey}}").strip()
        sudo("ln", "-sfT", ns, "/var/run/netns/benchmark")

        # Set the default TTL for outgoing packets to the common
        # value 64, so that packets sent from router will match the expected value.
        sudo("ip", "netns", "exec", "benchmark", "sysctl", "-w", "net.ipv4.ip_default_ttl=64")

        # Run test brload test with --show-interfaces and set up the veth that it needs.
        # The router uses one end and the test uses the other end to feed it with (and possibly
        # capture) traffic.
        # We supply the label->(host-side-name,mac,peermac) mapping to brload when we start it.
        self.intfMap = {}
        brload = self.get_executable("brload")
        output = brload("show-interfaces")

        for line in output.splitlines():
            elems = line.split(",")
            if len(elems) != 4:
                continue
            t = IntfReq._make(elems)
            self.create_interface(t, "benchmark")

        # We don't need that symlink any more
        sudo("rm", "/var/run/netns/benchmark")

        # Now the router can start.
        docker("run",
               "-v", f"{self.artifacts}/conf:/share/conf",
               "-d",
               "-e", "SCION_EXPERIMENTAL_BFD_DISABLE=true",
               "-e", "GOMAXPROCS=4",
               "--network", "container:prometheus",
               "--name", "router",
               "posix-router:latest")

        time.sleep(2)

    def teardown(self):
        docker["logs", "router"].run_fg(retcode=None)
        docker("rm", "-f", "prometheus")
        docker("rm", "-f", "router")
        docker("network", "rm", "benchmark")  # veths are deleted automatically
        sudo("chown", "-R", whoami().strip(), self.artifacts)

    def execBrLoad(self, case: str, mapArgs: list[str], count: int) -> str:
        brload = self.get_executable("brload")
        return sudo(brload.executable,
                    "run",
                    "--artifacts", self.artifacts,
                    *mapArgs,
                    "--case", case,
                    "--num-packets", str(count),
                    "--num-streams", "2")

    def runTestCase(self, case: str, mapArgs: list[str]):
        logger.info(f"==> Starting load {case}")

        output = self.execBrLoad(case, mapArgs, 10000000)
        for line in output.splitlines():
            print(line)
            if line.startswith('metricsBegin'):
                _, beg, _, end = line.split()

        logger.info(f"==> Collecting {case} performance metrics...")

        # The raw metrics are expressed in terms of core*seconds. We convert to machine*seconds
        # which allows us to provide a projected packet/s; ...more intuitive than packets/core*s.
        # We're interested only in br_transit traffic. We measure the rate over 10s. For best
        # results we sample the end of the middle 10s of the run. "beg" is the start time of the
        # real action and "end" is the end time.
        sampleTime = (int(beg) + int(end) + 10) / 2
        promQuery = urlencode({
            'time': f'{sampleTime}',
            'query': (
                'sum by (instance, job) ('
                f'  rate(router_output_pkts_total{{job="BR", type="{case}"}}[10s])'
                ')'
                '/ on (instance, job) group_left()'
                'sum by (instance, job) ('
                '  1 - (rate(process_runnable_seconds_total[10s])'
                '       / go_sched_maxprocs_threads)'
                ')'
            )
        })
        conn = HTTPConnection("localhost:9999")
        conn.request('GET', f'/api/v1/query?{promQuery}')
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f'Unexpected response: {resp.status} {resp.reason}')

        # There's only one router, so whichever metric we get is the right one.
        pld = json.loads(resp.read().decode('utf-8'))
        results = pld['data']['result']
        for result in results:
            ts, val = result['value']
            return int(float(val))
        return 0

    # Fetch and log the number of cores used by Go. This may inform performance
    # modeling later.
    def logCoreCounts(self):
        logger.info('==> Collecting number of cores...')
        promQuery = urlencode({
            'query': 'go_sched_maxprocs_threads{job="BR"}'
        })

        conn = HTTPConnection("localhost:9999")
        conn.request('GET', f'/api/v1/query?{promQuery}')
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f'Unexpected response: {resp.status} {resp.reason}')

        pld = json.loads(resp.read().decode('utf-8'))
        results = pld['data']['result']
        for result in results:
            instance = result['metric']['instance']
            _, val = result['value']
            logger.info(f'Router Cores for {instance}: {int(val)}')

    def _run(self):
        # Build the interface mapping arg
        mapArgs = []
        for label, intf in self.intfMap.items():
            mapArgs.extend(["--interface", f"{label}={intf.name},{intf.mac},{intf.peerMac}"])

        # Run one (10% size) test as warm-up to trigger the frequency scaling, else the first test
        # gets much lower performance.
        self.execBrLoad(list(TEST_CASES)[0], mapArgs, 1000000)

        # At long last, run the tests
        rateMap = {}
        for testCase in TEST_CASES:
            rateMap[testCase] = self.runTestCase(testCase, mapArgs)

        self.logCoreCounts()

        # Log and check the performance...
        # If this is used as a CI test. Make sure that the performance is within the expected
        # ballpark.
        rateTooLow = []
        for tt, exp in TEST_CASES.items():
            if self.ci and exp != 0:
                logger.info(f'Packets/(machine*s) for {tt}: {rateMap[tt]} expected: {exp}')
                if rateMap[tt] < 0.8 * exp:
                    rateTooLow.append(tt)
            else:
                logger.info(f'Packets/(machine*s) for {tt}: {rateMap[tt]}')

        if len(rateTooLow) != 0:
            raise RuntimeError(f'Insufficient performance for: {rateTooLow}')


if __name__ == "__main__":
    base.main(RouterBMTest)
