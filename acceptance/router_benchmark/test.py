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

import logging
import json
import yaml
from http.client import HTTPConnection
from urllib.parse import urlencode
from plumbum import cli
from plumbum.cmd import cat, grep, wc

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

# Those values are valid expectations only when running in the CI environment.
EXPECTATIONS = {
    'in': 53000,
    'out': 26000,
    'in_transit': 73000,
    'out_transit': 49000,
    'br_transit': 73000,
}


class Test(base.TestTopogen):
    """
    Tests that the performance of the router is within a satisfying (TBD) range.
    The test runs in a bespoke topology.
    """

    ci = cli.Flag(
        "ci",
        help="Do extra checks for CI",
        envname="CI"
    )

    def setup_prepare(self):
        super().setup_prepare()

        # The expected topology for this test is well-known: see router_bm.topo
        # This test is configured to match.

        # Distribute available cores among routers. The base schema is expressed as fractions of 12.
        # Then we scale and round.

        childRouterCores = 2  # *2
        farRouterCores = 2  # *1
        centerRouterCores = 3  # *2
        availCores = int((cat['/proc/cpuinfo'] | grep['processor\\s:'] | wc['-l'])())

        childRouterCores = int(childRouterCores * availCores / 12)
        farRouterCores = int(farRouterCores * availCores / 12)
        centerRouterCores = int(centerRouterCores * availCores / 12)

        if childRouterCores < 1:
            childRouterCores = 1

        if farRouterCores < 1:
            farRouterCores = 1

        if centerRouterCores < 1:
            centerRouterCores = 1

        availCores -= (2 * childRouterCores + 2 * centerRouterCores + farRouterCores)

        # The truncations can leave us with up to 4 extra cores. Give first to the center routers,
        # if there's enough.
        if availCores > 1:
            availCores -= 2
            centerRouterCores += 1

        # The leftovers go to childRouterCores, even if it means allocating one extraneous core.
        if availCores > 0:
            childRouterCores += 1

        coreCountUpdates = {
            'br1-ff00_0_110-1': centerRouterCores,
            'br1-ff00_0_110-2': centerRouterCores,
            'br1-ff00_0_111-1': childRouterCores,
            'br1-ff00_0_112-1': childRouterCores,
            'br2-ff00_0_120-1': farRouterCores,
        }

        # Edit GOMAXPROC for all routers in the docker compose file.
        scion_dc = self.artifacts / "gen/scion-dc.yml"
        with open(scion_dc, "r") as file:
            dc = yaml.load(file, Loader=yaml.FullLoader)

        for router, coreCnt in coreCountUpdates.items():
            dc["services"][router]["environment"]["GOMAXPROCS"] = f"{coreCnt}"

        with open(scion_dc, "w") as file:
            yaml.dump(dc, file)

    def setup(self):
        super().setup()
        self.monitoring_dc = docker.Compose(compose_file=self.artifacts / "gen/monitoring-dc.yml")
        self.monitoring_dc("up", "-d")

    def _run(self):
        # Give some time for the topology to start.
        self.await_connectivity()

        # Start as-transiting load. With the router_bm topology

        # The subset noncore#nonlocalcore gives us outgoing traffic at each
        # child, incoming traffic at BR-B, AS-transit-in traffic at BR-A1,
        # and AS-transit-out traffic at BR-A2. There is a small amount of
        # in and out traffic everywhere, on top of that produced by the test.
        # We only consider the routers involved in the test. Those see much
        # higher rates... we use that to isolate them in the results without
        # having to compare instance labels with the topology data.
        logger.info("==> Starting load as-transit")
        loadtest = self.get_executable("end2end_integration")
        retCode, stdOut, stdErr = loadtest[
            "-d",
            "-outDir", self.artifacts,
            "-name", "router_benchmark",
            "-cmd", "./bin/end2endblast",
            "-attempts", 1500000,
            "-timeout", "120s",  # Timeout is for all attempts together
            "-parallelism", 100,
            "-subset", "noncore#core#remoteISD"
        ].run_tee()

        for line in stdOut.splitlines():
            if line.startswith('metricsBegin'):
                _, beg, _, end = line.split()

        logger.info('==> Collecting in/out/as-transit performance metrics...')

        # The raw metrics are expressed in terms of core*seconds. We convert to machine*seconds
        # which allows us to provide a projected packet/s; ...more intuitive than packets/core*s.
        # We measure the rate over 10s. For best results we sample the end of the middle 10s of the
        # run.  "beg" is the start time of the real action and "end" is the end time.
        sampleTime = (int(beg) + int(end) + 10) / 2
        promQuery = urlencode({
            'time': f'{sampleTime}',
            'query': (
                'sum by (instance, job, type) ('
                '  rate(router_output_pkts_total{job="BR"}[10s])'
                ')'
                '/ on (instance, job) group_left()'
                'sum by (instance, job) ('
                '  1 - (rate(process_runnable_seconds_total[10s])'
                '       / go_sched_maxprocs_threads)'
                ')'
            )
        })
        conn = HTTPConnection("localhost:9090")
        conn.request('GET', f'/api/v1/query?{promQuery}')
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f'Unexpected response: {resp.status} {resp.reason}')

        pld = json.loads(resp.read().decode('utf-8'))
        results = pld['data']['result']
        rateMap = {}
        for result in results:
            tt = result['metric']['type']
            ts, val = result['value']
            # 0 values should not enter in any averaging. In this test, a very
            # low rate means that the router wasn't involved in the test for
            # that traffic type. "Out" traffic is the only one that exists at
            # two routers. To cover that case, we average the rates for a given
            # traffic type.
            # TODO: figure a more reliable way to identify the tested routers.
            r = int(float(val))
            if r < 5000:  # Not a router of interest.
                continue
            if rateMap.get(tt) is None:
                rateMap[tt] = []
            rateMap[tt].append(r)
        for tt, rates in rateMap.items():
            total = 0
            for r in rates:
                total += r
            rateMap[tt] = int(total / len(rates))

        # Start br-transiting load.
        # The subset noncore#noncore gives us a mix of in and out traffic at
        # the childrem and pure BR-transit traffic at BR-A1.
        logger.info("==> Starting load br-transit")
        loadtest = self.get_executable("end2end_integration")
        retCode, stdOut, stdErr = loadtest[
            "-d",
            "-outDir", self.artifacts,
            "-name", "router_benchmark",
            "-cmd", "./bin/end2endblast",
            "-attempts", 1500000,
            "-timeout", "120s",  # Timeout is for all attempts together
            "-parallelism", 100,
            "-subset", "noncore#noncore#remoteAS"
        ].run_tee()

        for line in stdOut.splitlines():
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
        conn = HTTPConnection("localhost:9090")
        conn.request('GET', f'/api/v1/query?{promQuery}')
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f'Unexpected response: {resp.status} {resp.reason}')

        # There's only one router that has br_transit traffic.
        pld = json.loads(resp.read().decode('utf-8'))
        results = pld['data']['result']
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

        conn = HTTPConnection("localhost:9090")
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

    def teardown(self):
        self.monitoring_dc("down")
        super().teardown()


if __name__ == '__main__':
    base.main(Test)
