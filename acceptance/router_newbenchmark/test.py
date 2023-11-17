#!/usr/bin/env python3

# Copyright 2021 Anapaya Systems
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

from typing import List
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


def create_veth(host: str, container: str, ip: str, mac: str, ns: str, neighbors: List[str]):
    exec_sudo(f"ip link add {host} mtu 8000 type veth peer name {container} mtu 8000")
    exec_sudo(f"sysctl -qw net.ipv6.conf.{host}.disable_ipv6=1")
    exec_sudo(f"ip link set {host} up")
    exec_sudo(f"ip link set {container} netns {ns}")
    exec_sudo(f"ip netns exec {ns} sysctl -qw net.ipv6.conf.{container}.disable_ipv6=1")
    exec_sudo(f"ip netns exec {ns} ethtool -K  {container} rx off tx off")
    exec_sudo(f"ip netns exec {ns} ip link set {container} address {mac}")
    exec_sudo(f"ip netns exec {ns} ip addr add {ip} dev {container}")
    for n in neighbors:
        exec_sudo(f"ip netns exec {ns} ip neigh add {n} "
             f"lladdr f0:0d:ca:fe:be:ef nud permanent dev {container}")
    exec_sudo(f"ip netns exec {ns} ip link set {container} up")


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

    pause_tar = cli.SwitchAttr(
        "pause_tar",
        str,
        help="taball with the pause image",
    )

    def setup_prepare(self):
        super().setup_prepare()

        shutil.copytree("acceptance/router_newbenchmark/conf/", self.artifacts / "conf")
        exec_sudo("mkdir -p /var/run/netns")

        exec_docker("network create -d bridge benchmark")

        pause_image = exec_docker(f"image load -q -i {self.pause_tar}").rsplit(' ', 1)[1]
        exec_docker(f"run -d --network=benchmark --publish 9999:9090 --name pause {pause_image}")
        ns = exec_docker("inspect pause -f '{{.NetworkSettings.SandboxKey}}'").replace("'", "")

        # WTF do we need to alias the namespace to "pause" while creating the veths?
        exec_sudo(f"ln -sfT {ns} /var/run/netns/pause")
        self.create_veths("pause")
        exec_sudo("rm /var/run/netns/pause")

    def setup_start(self):
        super().setup_start()

        envs = ["SCION_EXPERIMENTAL_BFD_DISABLE=true"]
        exec_docker(f"run -v {self.artifacts}/conf:/share/conf "
                    "-d "
                    f"-e {' '.join(envs)} "
                    "--network container:pause "
                    "--name router "
                    "bazel/acceptance/router_newbenchmark:router")

        exec_docker(f"run -v {self.artifacts}/conf:/share/conf "
                    "-d "
                    "--network container:pause "
                    "--name prometheus "
                    "prom/prometheus:v2.47.2 "
                    "--config.file /share/conf/prometheus.yml")

        time.sleep(2)

    def teardown(self):
        docker["logs", "router"].run_fg(retcode=None)
        exec_docker("rm -f prometheus")
        exec_docker("rm -f router")
        exec_docker("rm -f pause")  # veths are deleted automatically
        exec_docker("network rm benchmark")
        exec_sudo(f"chown -R {whoami()} {self.artifacts}")

    # Wire virtual interfaces around the one router that we run.
    def create_veths(self, ns: str):
        # Set default TTL for outgoing packets to the common value 64, so that packets sent
        # from router will match the expected value.
        exec_sudo(f"ip netns exec {ns} sysctl -w net.ipv4.ip_default_ttl=64")
        create_veth("veth_int_host", "veth_int", "192.168.0.1/24", "f0:0d:ca:fe:00:01", ns,
                    ["192.168.0.2"])
        create_veth("veth_2_host", "veth_2", "192.168.2.1/24", "f0:0d:ca:fe:00:02", ns,
                    ["192.168.2.2"])
        create_veth("veth_3_host", "veth_3", "192.168.3.1/24", "f0:0d:ca:fe:00:03", ns,
                    ["192.168.3.3"])

    def _run(self):
        logger.info("==> Starting load br-transit")
        brload = self.get_executable("brload")
        output = exec_sudo(f"{brload.executable} -artifacts {self.artifacts} "
                           "-case br_transit -num_packets 5000000")
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
