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
from typing import List, Tuple
from plumbum import cli
from plumbum.cmd import sudo,docker,whoami

from acceptance.common import base

import logging
import json
import yaml
from http.client import HTTPConnection
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# Those values are valid expectations only when running in the CI environment.
EXPECTATIONS = {
    # 'in': 53000,
    # 'out': 26000,
    # 'in_transit': 73000,
    # 'out_transit': 49000,
    'br_transit': 73000,
}


def exec_docker(command: str) -> str:
    return docker(str.split(command))


def exec_sudo(command: str) -> str:
    # -A, --askpass makes sure command is failing and does not wait for
    # interactive password input.
    return sudo("-A", str.split(command))


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
    Tests that the implementation of a router has sufficient performance (in terms of packets
    per available machine*second (i.e. one accumulated second of all configured CPUs available
    to execute the router code).

    This test depends on an image called pause. This image is very thin, 250KB,
    and is used to keep the network namespace open during the test. It is
    stored locally by executing `docker save kubernetes/pause > pause.tar`. It
    can be replaced at any time with any other image e.g. Alpine.

    This test runs and execute a single router. The outgoing packets are not observed, the incoming
    packets are fed directly by the test driver. The other routers in the topology are a fiction,
    they exist only in the routers configuration.

    The topology (./conf/topology.json) is the following:

    AS2 (br2) ---+== (br1a) AS1 (br1b) ---- (br4) AS4
                 |
    AS3 (br3) ---+

    Only br1 is executed and observed.

    Pretend traffic is injected as follows:

    * from AS2 to AS3 at br1a external interface 1 to cause "br_transit" traffic.
    * from AS2 to AS4 at br1a external interface 1 to cause "in_transit" traffic.
    * from AS2 to AS1 at br1a external interface 1 to cause "in" traffic.
    * from AS1 to AS2 at br1a internal interface to cause "out" traffic.
    * from AS4 to AS2 at br1a internal interface to cause "out_transit" traffic.
    """

    ci = cli.Flag(
        "ci",
        help="Do extra checks for CI",
        envname="CI"
    )

    # Accepts an IntfReq records names and mac addresses into an Intf and associates it with
    # the request label.
    def create_interface(self, req: IntfReq, ns: str) -> Intf:
        hostIntf = f"veth_{req.label}_host"
        brIntf = f"veth_{req.label}"
        peerMac = mac_for_ip(req.peerIp)
        mac = mac_for_ip(req.ip)
        exec_sudo(f"ip link add {hostIntf} mtu 8000 type veth peer name {brIntf} mtu 8000")
        exec_sudo(f"sysctl -qw net.ipv6.conf.{hostIntf}.disable_ipv6=1")
        exec_sudo(f"ip link set {hostIntf} up")
        exec_sudo(f"ip link set {brIntf} netns {ns}")
        exec_sudo(f"ip netns exec {ns} sysctl -qw net.ipv6.conf.{brIntf}.disable_ipv6=1")
        exec_sudo(f"ip netns exec {ns} ethtool -K  {brIntf} rx off tx off")
        exec_sudo(f"ip netns exec {ns} ip link set {brIntf} address {mac}")
        exec_sudo(f"ip netns exec {ns} ip addr add {req.ip}/{req.prefixLen} dev {brIntf}")
        exec_sudo(f"ip netns exec {ns} ip neigh add {req.peerIp} "
                  f"lladdr {peerMac} nud permanent dev {brIntf}")
        exec_sudo(f"ip netns exec {ns} ip link set {brIntf} up")
        self.intfMap[req.label] = Intf(hostIntf, mac, peerMac)

    def setup_prepare(self):
        super().setup_prepare()

        # get the config where the router can find it.
        shutil.copytree("acceptance/router_newbenchmark/conf/", self.artifacts / "conf")

        # We need a custom network so can create veth interfaces of our own chosing.
        exec_docker("network create -d bridge benchmark")

        # This test is useless without prometheus. Also, we need a running container to have
        # a usable network namespace that we can configuer before the router runs. So, start
        # prometheus now and then have the router share the same network stack.

        # FWIW, the alternative would be to start the router's container without the router,
        # configure the interfaces, and then start the router. We'd still need prometheus, though,
        # and we'd need to expose the router's metrics port to prometheus in some way. So, this is
        # simpler.
        exec_docker(f"run -v {self.artifacts}/conf:/share/conf "
                    "-d "
                    "--network benchmark "
                    "--publish 9999:9090 "
                    "--name prometheus "
                    "prom/prometheus:v2.47.2 "
                    "--config.file /share/conf/prometheus.yml")

        # Link that namespace to where the ip commands expect it. While at it give it a simple name.
        exec_sudo("mkdir -p /var/run/netns")
        ns = exec_docker("inspect prometheus -f '{{.NetworkSettings.SandboxKey}}'").replace("'", "")
        exec_sudo(f"ln -sfT {ns} /var/run/netns/benchmark")

        # Set default TTL for outgoing packets to the common value 64, so that packets sent
        # from router will match the expected value.
        exec_sudo("ip netns exec benchmark sysctl -w net.ipv4.ip_default_ttl=64")

        # Run test brload test with --show_interfaces and set up the veth that it needs.
        # The router uses one end and the test uses the other end to feed it with (and possibly
        # capture) traffic.
        # We supply the label->(host-side-name,mac,peermac) mapping to brload when we start it.
        self.intfMap = {}
        brload = self.get_executable("brload")
        output = exec_sudo(f"{brload.executable} -artifacts {self.artifacts} "
                           "-show_interfaces")

        for line in output.splitlines():
            elems = line.split(",")
            if len(elems) != 4:
                continue
            t = IntfReq._make(elems)
            self.create_interface(t, "benchmark")

        # We don't need that symlink any more
        exec_sudo("rm /var/run/netns/benchmark")

        # Now the router can start.
        exec_docker(f"run -v {self.artifacts}/conf:/share/conf "
                    "-d "
                    "-e SCION_EXPERIMENTAL_BFD_DISABLE=true -e GOMAXPROCS=6 "
                    "--network container:prometheus "
                    "--name router "
                    "bazel/acceptance/router_newbenchmark:router")

        time.sleep(2)

    def teardown(self):
        docker["logs", "router"].run_fg(retcode=None)
        exec_docker("rm -f prometheus")
        exec_docker("rm -f router")
        exec_docker("network rm benchmark") # veths are deleted automatically
        exec_sudo(f"chown -R {whoami()} {self.artifacts}")

    def _run(self):
        # Build the interface mapping arg:
        mapArgs = [f"-interface {label}={intf.name},{intf.mac},{intf.peerMac}"
                   for label, intf in self.intfMap.items()]

        # At long last...
        logger.info("==> Starting load br-transit")
        brload = self.get_executable("brload")
        output = exec_sudo(f"{brload.executable} -artifacts {self.artifacts} "
                           f"{' '.join(mapArgs)} "
                           "-case br_transit -num_packets 10000000 -num_streams 2")

        for line in output.splitlines():
            print(line)
            if line.startswith('metricsBegin'):
                _, beg, _, end = line.split()

        logger.info('==> Collecting br-transit performance metrics...')

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
                '  rate(router_output_pkts_total{job="BR", type="br_transit"}[10s])'
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

        # There's only one router that has br_transit traffic.
        pld = json.loads(resp.read().decode('utf-8'))
        results = pld['data']['result']
        rateMap = {}
        tt = 'br_transit'
        rateMap[tt] = 0
        for result in results:
            ts, val = result['value']
            r = int(float(val))
            if r != 0:
                rateMap[tt] = r

        # Fetch and log the number of cores used by Go. This may inform performance
        # modeling later.
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

        # Log and check the performance...
        # If this is used as a CI test. Make sure that the performance is within the expected
        # ballpark.
        rateTooLow = []
        for tt, exp in EXPECTATIONS.items():
            if self.ci:
                logger.info(f'Packets/(machine*s) for {tt}: {rateMap[tt]} expected: {exp}')
                if rateMap[tt] < 0.8 * exp:
                    rateTooLow.append(tt)
            else:
                logger.info(f'Packets/(machine*s) for {tt}: {rateMap[tt]}')

        if len(rateTooLow) != 0:
            raise RuntimeError(f'Insufficient performance for: {rateTooLow}')


if __name__ == "__main__":
    base.main(RouterBMTest)
