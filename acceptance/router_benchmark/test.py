#!/usr/bin/env python3

# Copyright 2020 Anapaya Systems
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

import logging
import json
import time
from http.client import HTTPConnection

from acceptance.common import base, docker

logger = logging.getLogger(__name__)

# This test relies ona specific topology router_bm.topo.
# This topology is 1 core AS with two children and one core AS with none like so:
#
#       CoreAS-A      CoreAS-B
#    BR-A1   BR-A2 ---- BR-B
#    |   |
# BR-C   BR-D
# AS-C   AS-D


class Test(base.TestTopogen):
    """
    Tests that the performance of the router is within a satisfying (TBD) range.
    The test runs in a bespoke topology.
    """

    def setup(self):
        super().setup()
        self.monitoring_dc = docker.Compose(project="monitoring",
                                            compose_file=self.artifacts / "gen/monitoring-dc.yml")
        self.monitoring_dc("up", "-d")

    def _run(self):
        # Give some time for the topology to start.
        time.sleep(10)

        # Start as-transiting load. With the router_bm topology

        # The subset noncore#nonlocalcore gives us outgoing traffic at each
        # child, incoming traffic at BR-B, AS-transit-in traffic at BR-A1,
        # and AS-transit-out traffic at BR-A2. No traffic mix anywhere.
        logger.info("==> Starting load as-transit")
        loadtest = self.get_executable("end2end_integration")
        loadtest[
            "-d",
            "-traces=false",
            "-outDir", self.artifacts,
            "-name", "router_benchmark",
            "-game", "packetflood",
            "-attempts", 5000,
            "-parallelism", 100,
            "-subset", "noncore#core#remoteISD"
        ].run_fg()

        logger.info('==> Collecting in/out/as-transit performance metrics...')

        # Very dumb query for now. Will make right later, when good metrics become available.
        conn = HTTPConnection("localhost:9090")
        conn.request('GET', '/api/v1/query?query=rate(router_processed_pkts_total%5B1m%5D)')
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f'Unexpected response: {resp.status} {resp.reason}')

        pld = json.loads(resp.read().decode('utf-8'))
        results = pld['data']['result']
        for result in results:
            print("labels: {")
            for label, value in result['metric'].items():
                print(f'{label}={value},')
            print("}")
            ts, val = result['value']
            print(f'value: {val}')
            print(f'timestamp: {ts}')

        # Start br-transiting load.
        # The subset noncore#noncore gives us a mix of in and out traffic at
        # the childrem and pure BR-transit traffic at BR-A1.
        logger.info("==> Starting load br-transit")
        loadtest = self.get_executable("end2end_integration")
        loadtest[
            "-d",
            "-traces=false",
            "-outDir", self.artifacts,
            "-name", "router_benchmark",
            "-game", "packetflood",
            "-attempts", 5000,
            "-parallelism", 100,
            "-subset", "noncore#noncore#remoteAS"
        ].run_fg()

        logger.info('==> Collecting br-transit performance metrics...')

        # Very dumb query for now. Will make right later, when good metrics become available.
        conn = HTTPConnection("localhost:9090")
        conn.request('GET', '/api/v1/query?query=rate(router_processed_pkts_total%5B1m%5D)')
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f'Unexpected response: {resp.status} {resp.reason}')

        pld = json.loads(resp.read().decode('utf-8'))
        results = pld['data']['result']
        for result in results:
            print("labels: {")
            for label, value in result['metric'].items():
                print(f'{label}={value},')
            print("}")
            ts, val = result['value']
            print(f'value: {val}')
            print(f'timestamp: {ts}')

    def teardown(self):
        self.monitoring_dc("down")
        super().teardown()


if __name__ == '__main__':
    base.main(Test)
