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


import ipaddress
import json
import logging
import os
import shutil
import signal
import sys
import time
import ssl

from collections import defaultdict, namedtuple
from http.client import HTTPConnection
from http.client import HTTPSConnection
from plumbum import cli
from plumbum import cmd
from plumbum import local
from plumbum.cmd import docker, whoami, lscpu
from random import randint
from urllib.parse import urlencode
from urllib.request import urlopen

TEST_CASES = [
    "in",
    "out",
    "in_transit",
    "out_transit",
    "br_transit",
]

# A magic coefficient used in calculating the performance index.
M_CONSTANT = 18500

# TODO(jiceatscion): get it from or give it to brload?
BM_PACKET_LEN = 172

# Convenience types to carry interface params.
IntfReq = namedtuple("IntfReq", "label, prefixLen, ip, peerIp, exclusive")


def sudo(*args: [str]) -> str:
    # -A, --askpass makes sure command is failing and does not wait for
    # interactive password input.
    return cmd.sudo("-A", *args)


class RouterBM:
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

    """

    intfMap: dict[str, str] = {}
    availInterfaces: list[str] = []
    mxInterface: str = None
    toFlush: list[str] = []
    scrapeAddr: str = None

    def __init__(self):
        """Collect the givens."""
        self.artifacts = f"{os.getcwd()}/acceptance/router_benchmark"

    def host_interface(self, excl: bool):
        """Returns the next host interface that we should use for a brload links.

        If excl is true, we pick one and never pick that one again.
        Else, we pick one the first time it's needed and keep it for reuse.
        """
        if excl:
            return self.availInterfaces.pop()
        
        if self.mxInterface is None:
            self.mxInterface = self.availInterfaces.pop()

        return self.mxInterface
    
    def config_interface(self, req: IntfReq):
        """Configure an interfaces according to brload's requirements.

        The device must not be in use for anything else. The devices are picked from a list
        supplied by the user.

        We probably do not:
          sudo("ip", "addr", "add", f"{req.peerIp}/{req.prefixLen}", "dev", hostIntf)

        It causes trouble: if an IP is assigned, the kernel responds with "unbound port" icmp
        messages to the router traffic, which breaks the bound UDP connections that the router uses
        for external interfaces.

        Args:
          IntfReq: A requested router-side network interface. It comprises:
                   * A label by which brload identifies that interface.
                   * The IP address to be assigned to that interface.
                   * The IP address of one neighbor.

        """
        exclusive = req.exclusive == "true"
        hostIntf = self.host_interface(exclusive)

        # We need a means of connecting to the router's internal interface (from prometheus and
        # to scrape the horsepower microbenchmark results. We pick one address of
        # the router's subnet that's not otherwise used. This must NOT be "PeerIP".
        # brload requires the internal interface to be "exclusive", that's our clue.
        if exclusive:
            net = ipaddress.ip_network(f"{req.ip}/{req.prefixLen}", strict=False)
            hostAddr = next(net.hosts()) + 126
            self.scrapeAddr = req.ip
            sudo("ip", "addr", "add", f"{hostAddr}/{req.prefixLen}",
                 "broadcast", str(net.broadcast_address), "dev", hostIntf)
            self.toFlush.append(hostIntf)

        print(f"=> Configuring interface {hostIntf} for: {req}...")

        # We do multiplex most requested router interfaces onto one physical interface, so, we
        # must check that we haven't already configured the physical one.
        for name in self.intfMap.values():
            if name == hostIntf:
                break
        else:
            # TODO: instructions/warning regarding inability to enable jumbo frames.
            # sudo("ip", "link", "set", hostIntf, "mtu", "8000")

            # Do not assign the host addresses but create one link-local addr.
            # Brload needs some src IP to send arp requests. (This requires rp_filter
            # to be off on the router side, else, brload's arp requests are discarded).
            sudo("ip", "addr", "add", f"169.254.{randint(0, 255)}.{randint(0, 255)}/16",
                 "broadcast", "169.254.255.255",
                 "dev", hostIntf, "scope", "link")
            sudo("sysctl", "-qw", f"net.ipv6.conf.{hostIntf}.disable_ipv6=1")
            self.toFlush.append(hostIntf)

        # Fit for duty.
        sudo("ip", "link", "set", hostIntf, "up")

        # Ship it.
        self.intfMap[req.label] = hostIntf

    def setup(self, availInterfaces: list[str]):
        print("Preparing...")

        # Check that the given interfaces are safe to use. We will wreck their config.
        for intf in availInterfaces:
            output = sudo("ip", "addr", "show", "dev", intf)
            if len(output.splitlines()) > 2:
                print(f"""\
                Interface {intf} appears to be in some kind of use. Cowardly refusing to modify it.
                If you have a network manager, tell it to disable or ignore that interface.
                Else, how about \"sudo ip addr flush dev {intf}\"?
                """)
                raise RuntimeError("Interface in use")

        # Looks safe.
        self.availInterfaces = availInterfaces

        # Run test brload test with --show-interfaces and set up the interfaces as it says.
        # We supply the label->host-side-name mapping to brload when we start it.
        print("==> Configuring host interfaces...")

        brload = local["./bin/brload"]
        output = brload("show-interfaces")

        lines = sorted(output.splitlines())
        for line in lines:
            print(f"Requested by brload: {line}")
            elems = line.split(",")
            if len(elems) != 5:
                continue
            t = IntfReq._make(elems)
            self.config_interface(t)

        # Start an instance of prometheus configured to scrape the router.
        print("==> Starting prometheus...")
        docker("run",
               "-v", f"{self.artifacts}/conf:/etc/scion",
               "-d",
               "--network", "host",
               "--name", "prometheus_bm",
               "prom/prometheus:v2.47.2",
               "--config.file", "/etc/scion/prometheus.yml")

        time.sleep(2)
        print("Prepared")

    def teardown(self):
        print("Cleaning...")
        docker("rm", "-f", "prometheus_bm")
        for intf in self.toFlush:
            sudo("ip", "addr", "flush", "dev", intf)
        print("Cleaned")

    def exec_br_load(self, case: str, mapArgs: list[str], count: int) -> str:
        brload = local["./bin/brload"]
        # For num-streams, attempt to distribute uniformly on many possible number of cores.
        # 840 is a multiple of 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 15, 20, 21, 24, 28, ...
        return sudo(brload.executable,
                    "run",
                    "--artifacts", self.artifacts,
                    *mapArgs,
                    "--case", case,
                    "--num-packets", str(count),
                    "--num-streams", "840")

    def run_test_case(self, case: str, mapArgs: list[str]) -> (int, int):
        print(f"==> Starting load {case}")

        output = self.exec_br_load(case, mapArgs, 10000000)
        beg = "0"
        end = "0"
        for line in output.splitlines():
            if line.startswith("metricsBegin"):
                _, beg, _, end = line.split()

        print(f"==> Collecting {case} performance metrics...")

        # The raw metrics are expressed in terms of core*seconds. We convert to machine*seconds
        # which allows us to provide a projected packet/s; ...more intuitive than packets/core*s.
        # We measure the rate over 10s. For best results we sample the end of the middle 10s of the
        # run. "beg" is the start time of the real action and "end" is the end time.
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
        conn = HTTPConnection("localhost:9090")
        conn.request("GET", f"/api/v1/query?{promQuery}")
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

        # Collect dropped packets metrics, so we can verify that the router was well saturated.
        # If not, the metrics aren't very useful.
        promQuery = urlencode({
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
        conn = HTTPConnection("localhost:9090")
        conn.request("GET", f"/api/v1/query?{promQuery}")
        resp = conn.getresponse()
        if resp.status != 200:
            print(f"FAILED: Unexpected response: {resp.status} {resp.reason}")
            exit(1)

        # There's only one router, so whichever metric we get is the right one.
        pld = json.loads(resp.read().decode("utf-8"))
        dropped = 0
        results = pld["data"]["result"]
        for result in results:
            ts, val = result["value"]
            dropped = int(float(val))
            break

        return processed, dropped

    # Fetch and log the number of cores used by Go. This may inform performance
    # modeling later.
    def core_count(self) -> int:
        print("==> Collecting number of cores...")
        promQuery = urlencode({
            'query': 'go_sched_maxprocs_threads{job="BR"}'
        })

        conn = HTTPConnection("localhost:9090")
        conn.request("GET", f"/api/v1/query?{promQuery}")
        resp = conn.getresponse()
        if resp.status != 200:
            print(f"FAILED: Unexpected response: {resp.status} {resp.reason}")
            exit(1)

        pld = json.loads(resp.read().decode("utf-8"))
        results = pld["data"]["result"]
        if len(results) > 1:
            print(f"FAILED: Found more than one subject router in results: {results}")
            exit(1)

        result = results[0]
        instance = result["metric"]["instance"]
        _, val = result["value"]
        print(f"Router Cores for {instance}: {int(val)}")
        return int(val)

    def horsepower(self) -> tuple[int]:
        resp = urlopen(f"https://{self.scrapeAddr}/horsepower.txt",
                       context=ssl._create_unverified_context())
        if resp.status != 200:
            return 0,0
        try:
            hp = json.loads(resp.read().decode("ascii"))
        except json.JSONDecodeError:
            return 0, 0

        return round(hp["coremark"]), round(hp["mmbm"])

    def perf_index(self, rate: int, coremark: int, mmbm: int) -> float:
        # mmbm is in mebiBytes/s, rate is in pkt/s
        return rate * (1.0 / coremark + M_CONSTANT * BM_PACKET_LEN / (mmbm * 1024 * 1024))

    def run(self):
        print("Benchmarking...")

        # Collect the horsepower microbenchmark numbers if we can:
        coremark, mmbm = self.horsepower()
        coremarkstr = str(coremark or "Unavailable")
        mmbmstr = str(mmbm or "Unavailable")
        print(f"Coremark: {coremarkstr}")
        print(f"Memory bandwidth (MiB/s): {mmbmstr}")

        # Build the interface mapping arg (here, we do not override the brload side mac address)
        mapArgs = []
        for label, intf in self.intfMap.items():
            mapArgs.extend(["--interface", f"{label}={intf}"])

        # Run one test (30% size) as warm-up to trigger any frequency scaling, else the first test
        # can get much lower performance.
        print("Warmup")
        self.exec_br_load(TEST_CASES[0], mapArgs, 3000000)

        # At long last, run the tests
        rateMap = {}
        droppageMap = {}
        for testCase in TEST_CASES:
            print(f"Case: {testCase}")
            processed, dropped = self.run_test_case(testCase, mapArgs)
            rateMap[testCase] = processed
            droppageMap[testCase] = dropped

        cores = self.core_count()

        # Output the performance...
        for tt in TEST_CASES:
            print(f"Packets/(machine*s) for {tt}: {rateMap[tt]}")

        if coremark != 0 and mmbm != 0:
            for tt in TEST_CASES:
                # TODO(jiceatscion): The perf index assumes that line speed isn't the bottleneck.
                # It almost never is, but ideally we'd need to run iperf3 to verify.
                if cores == 3:
                    print(f"Perf index for {tt}: "
                          f"{self.perf_index(rateMap[tt], coremark, mmbm): .1f}")
                else:
                    priint(f"Perf index for {tt}: undefined for {cores} cores")

        # Check the saturation...
        # Make sure that the saturation is within the expeected ballpark: that should manifest as
        # some measurable amount of loss due to queue overflow.
        notSaturated = []
        for tt in TEST_CASES:
            total = rateMap[tt] + droppageMap[tt]
            if total == 0:
                print(f"WARNING: Droppage ratio unavailable for {tt}")
            else:
                ratio = float(droppageMap[tt]) / total
                exp = 0.03
                print(f"Droppage ratio for {tt}: {ratio:.1%} preferred: {exp:.1%}")

                if ratio < exp:
                    notSaturated.append(tt)

        if len(notSaturated) != 0:
            print(f"WARNING: Insufficient saturation for: {notSaturated}")

        print("Benchmarked")

    def instructions(self):
        brload = local["./bin/brload"]
        output = brload("show-interfaces")

        exclusives = []
        multiplexed = []
        reqs = []
        intfIndex = 0

        # We sort the requests from brload because the interface that is picked for each can depends
        # on the order in which we process them and we need to be consistent from run to run so
        # the instructions we give the user actually work.
        # (assuming brload's code doesn't change in-between).

        lines = sorted(output.splitlines())
        for line in lines:
            elems = line.split(",")
            if len(elems) != 5:
                continue
            req = IntfReq._make(elems)
            reqs.append(req)
            self.availInterfaces.append(str(intfIndex))  # Use numbers as placeholders
            intfIndex += 1

        # TODO: Because of multiplexing, there are fewer real interfaces than labels requested
        # by brload. So, not all placeholders get used (fine) and it happens that the low indices
        # are the ones not used (confusing for the user). Currently we end-up with 1 and 2
        # (and no 0), which is acceptable but fortuitous.
        for req in reqs:
            e = req.exclusive == "true"
            a = f"{req.ip}/{req.prefixLen}"
            i = self.host_interface(e)
            if e:
                exclusives.append(f"{a} (must reach: #{i})")
            else:
                multiplexed.append(f"{a} (must reach: #{i})")

        print(f"""
INSTRUCTIONS: 

1 - Configure your subject router according to accept/router_benchmark/conf/router.toml")
    If using openwrt, an easy way to do that is to install the bmtools.ipk package. In addition,
    bmtools includes two microbenchmarks: scion-coremark and scion-mmbm. Those will run
    automatically and the results will be used to improve the benchmark report.

    Optinal: If you did not install bmtools.ipk, install and run those microbenchmark and make a
    note of the results: (scion-coremark; scion-mmbm).

2 - Configure the following interfaces on your router (The procedure depends on your router
    UI):
    - One physical interface with addresses: {", ".join(multiplexed)}
{'\n'.join(['    - One physical interface with address: ' + s for s in exclusives])}

    IMPORTANT: if you're using a partitioned network (eg. multiple switches or no switches),
    the "must reach" annotation matters. The 'h' number is the order in which the corresponding host
    interface must be given on the command line in step 7.

3 - Connect the corresponding ports into your test switch (best if dedicated for the test).

4 - Restart the scion-router service.

5 - Pick the same number of physical interfaces on the system where you are running this
    script. Make sure that these interface aren't used for anything else and have no assigned
    IP addresses. Make a note of their names and, if using a partitioned network, associate each
    with one of the numbers from step 2.

6 - Connect the corresponding ports into your test switch. If using a partitioned network, make
    sure that port is reachable by the corresponding subject router port.

7 - Execute this script with arguments: --run <interfaces>, where <interfaces> is the list
    of names you collected in step 5. If using a partitioned network, make sure to supply them
    in the order indicated in step 2.
    
    Coming soon: if you want the report to include a performance index and have run coremark and
    mmbm manually, add the following arguments: "--coremark=<coremark>", "--mmbm=<mmbm>", where
    <coremark> and <mmbm> are the results you optionally collected in step 1.

8 - Be patient...

9 - Read the report.
""")

if __name__ == "__main__":

    bm = RouterBM()
    
    def signal_handler(sig, frame):
        bm.teardown()
        print("Running for the exit...")
        sys.exit(0)

    if "--run" not in sys.argv:
        bm.instructions()
        exit(1)
    sys.argv.remove("--run")
    signal.signal(signal.SIGINT, signal_handler)
    try:
        bm.setup(sys.argv[1:])
        bm.run()
    finally:
        bm.teardown()
    exit(0)
