#!/usr/bin/env python3

# Copyright 2024 SCION Association
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

# Benchmarking code that is common to the CI benchmark test and the stand-alone
# benchmark program.

import json
import logging

from collections import namedtuple
from http.client import HTTPConnection
from plumbum import cmd
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# TODO(jchugly): this is still a work in progress. There are two unknowns in the model.
# M_COEF: the proportion by which memory performance contributes to throughput compared to
# arithmetic performance. NIC_CONSTANT: the fixed cost of the kernel interacting with the hardware
# to retrieve a frame. That one is hardware dependent and must be found by a third benchmark, so
# it is not theoretically a constant, but keeping it here to not forget. Until then, our performance
# index isn't really valid cross-hardware. M_COEF=400 gives roughly consistent results with the
# hardware we have. So, using that until we know more. NIC_CONSTANT seems to be around
# 1 microsecond. Using that, provisionally.

M_COEF = 400
NIC_CONSTANT = 1.0/1000000

# Intf: description of an interface configured for brload's use. Depending on context
# mac and peermac may be unused. "mac" is the MAC address configured on the side of the subject
# router. "peer_mac" is the MAC address that brload should use when simulating the peer router.
# If peer_mac is unset, we'll let brload use the true MAC address on its side, which is the default.
Intf = namedtuple("Intf", "name, mac, peer_mac")


class Results:
    """Stores and format benchmark results.
    """

    cores: int = 0
    coremark: int = 0
    mmbm: int = 0
    packet_size: int = 0
    cases: list[dict] = []
    failed: list[dict] = []
    checked: bool = False

    def __init__(self, cores: int, coremark: int, mmbm: int, packet_size: int):
        self.cores = cores
        self.coremark = coremark
        self.mmbm = mmbm
        self.packet_size = packet_size

    def perf_index(self, rate: int) -> float:
        # TODO(jiceatscion): The perf index assumes that line speed isn't the bottleneck.
        # It almost never is, but ideally we'd need to run iperf3 to verify.
        # mmbm is in mebiBytes/s, rate is in pkt/s
        return rate * (1.0 / self.coremark +
                       M_COEF * self.packet_size / (self.mmbm * 1024 * 1024) +
                       NIC_CONSTANT)

    def add_case(self, name: str, rate: int, droppage: int, raw_rate: int):
        dropRatio = round(float(droppage) / (rate + droppage), 2)
        saturated = dropRatio > 0.03
        perf = 0.0
        if self.cores == 3 and self.coremark and self.mmbm:
            perf = round(self.perf_index(rate), 1)
        self.cases.append({"case": name,
                           "perf": perf, "rate": rate, "drop": dropRatio,
                           "bit_rate": rate * self.packet_size * 8,
                           "raw_pkt_rate": raw_rate,
                           "full": saturated})

    def CI_check(self, expectations: dict[str, int]):
        self.checked = True
        for tc in self.cases:
            want = expectations.get(tc["case"])
            if want is not None:
                slow = tc["rate"] < want
                unsaturated = not tc["full"]
                if slow or unsaturated:
                    self.failed.append({"case": tc["case"],
                                        "expected": want, "slow": slow, "unsaturated": unsaturated})

    def as_json(self) -> str:
        return json.dumps({
            "cores": self.cores,
            "coremark": self.coremark,
            "mmbm": self.mmbm,
            "cases": self.cases,
            "checked": self.checked,
            "failed": self.failed,
        }, indent=4)

    def as_report(self) -> str:
        res = (f"Benchmark Results\n\ncores: {self.cores}\n"
               f"coremark: {self.coremark or 'N/A'}\nmmbm: {self.mmbm or 'N/A'}\n")
        for tc in self.cases:
            res += (f"{tc['case']}: perf_index={tc['perf'] or 'N/A'}"
                    f" rate={tc['rate']} droppage={tc['drop']:.1%} saturated={tc['full']}\n")
        res += "CI pass/fail: "
        if not self.checked:
            res += "N/A\n"
            return res
        res += "FAILED\n" if self.failed else "PASS\n"
        if not self.failed:
            return res
        for failure in self.failed:
            res += (f"{failure['case']} expected={failure['expected']}"
                    f" slow={failure['slow']} unsaturated={failure['unsaturated']}")
        return res


class RouterBM():
    """Evaluates the performance of an external router running the SCION reference implementation.

    The performance is reported in terms of packets per available machine*second (i.e. one
    accumulated second of all configured CPUs available to execute the router code).

    The router can actually be anything that has compatible metrics scrapable by
    prometheus. So that's presumably the reference implementation or a fork thereof.

    This test runs against a single router. The outgoing packets are not observed, the incoming
    packets are fed directly by the test driver (brload). The other routers in the topology are a
    fiction, they exist only in the routers configuration.

    The topology (./conf/topology.json) is the following:

    AS2 (br2) ---+== (br1a) AS1 (br1b) ---- (br4) AS4
                 |
    AS3 (br3) ---+

    Only br1a is executed and observed.

    Pretend traffic is injected by brload's. See the test cases for details.

    This class is a Mixin that borrows the following attributes from the host class:
    * coremark: the coremark benchmark results.
    * mmbm: the mmbm benchmark results.
    * packet_size: the packet_size to use in the test cases.
    * intf_map: the map "label->actual_interface" map to be passed to brload.
    * brload: "localCmd" wraper for the brload executable (plumbum.machines.LocalCommand)
    * brload_cpus: [int] cpus where it is acceptable to run brload ([] means any)
    * artifacts: the data directory (passed to docker).
    * prom_address: the address of the prometheus API a string in the form "host:port"
    """

    def exec_br_load(self, case: str, map_args: list[str], duration: int) -> str:
        # For num-streams, attempt to distribute uniformly on many possible number of cores.
        # 840 is a multiple of 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 15, 20, 21, 24, 28, ...
        brload_args = [
            self.brload.executable,
            "run",
            "--artifacts", self.artifacts,
            *map_args,
            "--case", case,
            "--duration", f"{duration}s",
            "--num-streams", "840",
            "--packet-size", f"{self.packet_size}",
        ]
        if self.brload_cpus:
            brload_args = [
                "taskset", "-c", ",".join(map(str, self.brload_cpus)),
            ] + brload_args

        return cmd.sudo("-A", *brload_args)

    def run_test_case(self, case: str, map_args: list[str]) -> (int, int):
        logger.debug(f"==> Starting load {case}")

        # We transmit for 13 seconds and then ignore the first 3.
        output = self.exec_br_load(case, map_args, 13)
        end = "0"
        for line in output.splitlines():
            logger.info("BrLoad output: " + line)
            if line.startswith("metricsBegin"):
                end = line.split()[3]  # "... metricsEnd: <end>"

        logger.debug(f"==> Collecting {case} performance metrics...")

        # The raw metrics are expressed in terms of core*seconds. We convert to machine*seconds
        # which allows us to provide a projected packet/s; ...more intuitive than packets/core*s.
        # We measure the rate over 10s. For best results we only look at the last 10 seconds.
        # "end" reports a time when the transmission was still going on at maximum rate.
        sampleTime = int(end)
        prom_query = urlencode({
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
        conn = HTTPConnection(self.prom_address)
        conn.request("GET", f"/api/v1/query?{prom_query}")
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f"Unexpected response: {resp.status} {resp.reason}")

        # There's only one router, so whichever metric we get is the right one.
        pld = json.loads(resp.read().decode("utf-8"))
        processed = 0
        results = pld["data"]["result"]
        for result in results:
            ts, val = result["value"]
            processed = int(float(val))
            break

        # Collect the raw packet rate too. Just so we can discover if the cpu-availability
        # correction is bad.
        prom_query = urlencode({
            'time': f'{sampleTime}',
            'query': (
                'sum by (instance, job) ('
                f'  rate(router_output_pkts_total{{job="BR", type="{case}"}}[10s])'
                ')'
            )
        })
        conn = HTTPConnection(self.prom_address)
        conn.request("GET", f"/api/v1/query?{prom_query}")
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f"Unexpected response: {resp.status} {resp.reason}")

        # There's only one router, so whichever metric we get is the right one.
        pld = json.loads(resp.read().decode("utf-8"))
        raw = 0
        results = pld["data"]["result"]
        for result in results:
            ts, val = result["value"]
            raw = int(float(val))
            break

        # Collect dropped packets metrics, so we can verify that the router was well saturated.
        # If not, the metrics aren't very useful.
        prom_query = urlencode({
            'time': f'{sampleTime}',
            'query': (
                'sum by (instance, job) ('
                '  rate(router_dropped_pkts_total{job="BR", reason=~"busy_.*"}[10s])'
                ')'
                '/ on (instance, job) group_left()'
                'sum by (instance, job) ('
                '  1 - (rate(process_runnable_seconds_total[10s])'
                '       / go_sched_maxprocs_threads)'
                ')'
            )
        })
        conn = HTTPConnection(self.prom_address)
        conn.request("GET", f"/api/v1/query?{prom_query}")
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f"Unexpected response: {resp.status} {resp.reason}")

        # There's only one router, so whichever metric we get is the right one.
        pld = json.loads(resp.read().decode("utf-8"))
        dropped = 0
        results = pld["data"]["result"]
        for result in results:
            ts, val = result["value"]
            dropped = int(float(val))
            break

        return processed, dropped, raw

    # Fetch and log the number of cores used by Go. This may inform performance
    # modeling later.
    def core_count(self) -> int:
        logger.debug("==> Collecting number of cores...")
        prom_query = urlencode({
            'query': 'go_sched_maxprocs_threads{job="BR"}'
        })

        conn = HTTPConnection(self.prom_address)
        conn.request("GET", f"/api/v1/query?{prom_query}")
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f"FAILED: Unexpected response: {resp.status} {resp.reason}")

        pld = json.loads(resp.read().decode("utf-8"))
        results = pld["data"]["result"]
        if not results:
            raise RuntimeError("FAILED: Got no results when querying the core count")
        if len(results) > 1:
            raise RuntimeError(f"FAILED: Found more than one subject router in results: {results}")

        result = results[0]
        _, val = result["value"]
        return int(val)

    def run_bm(self, test_cases: [str]) -> Results:
        logger.info("Benchmarking...")

        # Build the interface mapping arg (here, we do not override the brload side mac address)
        map_args = []
        for label, intf in self.intf_map.items():
            if intf.peer_mac is not None:
                map_args.extend(["--interface", f"{label}={intf.name},{intf.peer_mac}"])
            else:
                map_args.extend(["--interface", f"{label}={intf.name}"])

        # Run one test (30% size) as warm-up to trigger any frequency scaling, else the first test
        # can get much lower performance.
        logger.debug("Warmup")
        self.exec_br_load(test_cases[0], map_args, 5)

        # Fetch the core count once. It doesn't change while the router is running.
        # We cannot get this until the router has been up for a few seconds. If you shorten
        # the warmup for some reason, make sure to add a delay.
        cores = self.core_count()

        # At long last, run the tests.
        results = Results(cores, self.coremark, self.mmbm, self.packet_size)
        for test_case in test_cases:
            logger.info(f"Case: {test_case}")
            rate, droppage, raw = self.run_test_case(test_case, map_args)
            results.add_case(test_case, rate or 1, droppage, raw)

        return results
        logger.info("Benchmarked")
