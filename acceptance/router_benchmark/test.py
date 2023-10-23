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
import toml
import sys
from http.client import HTTPConnection
from typing import List

from plumbum import local
from plumbum.path.local import LocalPath

from acceptance.common import base, docker, log

logger = logging.getLogger(__name__)


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

        logger.info("==> Starting load")
        loadtest = self.get_executable("router_loadtest")
        loadtest["-d", "-outDir", self.artifacts].run_fg()

        logger.info('==> Collecting performance metrics...')

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
