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

from collections import defaultdict, namedtuple
from plumbum import cli
from plumbum.cmd import docker, whoami, lscpu
from plumbum import cmd

from acceptance.common import base

import logging
import json
from http.client import HTTPConnection
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

# Those values are valid expectations only when running in the CI environment.
TEST_CASES = {
    "in": 720000,
    "out": 730000,
    "in_transit": 700000,
    "out_transit": 720000,
    "br_transit": 720000,
}


def sudo(*args: [str]) -> str:
    # -A, --askpass makes sure command is failing and does not wait for
    # interactive password input.
    return cmd.sudo("-A", *args)


# Convenience types to carry interface params.
IntfReq = namedtuple("IntfReq", "label, prefixLen, ip, peerIp, exclusive")
Intf = namedtuple("Intf", "name, mac, peerMac")


# Make-up an eth mac address as unique as the given IP.
# Assumes ips in a /16 or smaller block (i.e. The last two bytes are unique within the test).
def mac_for_ip(ip: str) -> str:
    ipBytes = ip.split(".")
    return "f0:0d:ca:fe:{:02x}:{:02x}".format(int(ipBytes[2]), int(ipBytes[3]))


def choose_cpus_from_unshared_cache(caches: list[int], cores: list[int]) -> list[int]:
    """Picks the cpus that the test must use.

    This variant try to collect only cpus that do not share an L2 cache (and so, not
    hyperthreaded either). This is not likely to succeed but on machines that can do that, it
    is the configuration that causes the least performance variability.

    Returns:
      A list of up to 4 vcpus. All are first choice.
    """

    chosen = [cpus[0] for cpus in caches.values() if len(cpus) == 1]

    logger.info(f"CPUs from unshared cache: best={len(chosen)}")
    return sorted(chosen)[0:4]


def choose_cpus_from_single_cache(caches: list[int], cores: list[int]) -> list[int]:
    """Picks the cpus that the test must use.

    This variant try to collect only cpus that are all in the same L2 cache but from
    non-hyper-threaded cores (best) or different ht cores (second best).

    This would be a fairly common configuration. It also provides consistent performance results
    as the shared cache will likely be used entirely by the test and not poluted by other random
    activities.

    Returns:
      A list of up to 4 vcpus. The ones at the head of the list are the best.
    """

    best = {cpus[0] for cpus in cores.values() if len(cpus) == 1}
    chosen = set()
    for cpus in caches.values():
        chosen = set(cpus) & best
        if len(chosen) >= 4:
            logger.info(f"CPUs from single cache: best={len(chosen)}")
            return sorted(chosen)[0:4]

    # Not enough. Add second-best CPUs (one from each hyperthreaded core)
    # and filter the cache sets again.
    second_best = {cpus[0] for cpus in cores.values() if len(cpus) > 1}
    acceptable = best | second_best
    chosen = set()
    best_top = 0
    for cpus in caches.values():
        chosen_too = set(cpus) & acceptable
        # chosen_too may contain some or all of the best cpus.
        best_cnt = len(chosen_too & best)
        if best_cnt > best_top:
            best_top = best_cnt
            chosen = chosen_too

    logger.info("CPUs from single cache: "
                f"best={len(chosen & best)} "
                f"second_best={len(chosen & second_best)}")

    return (sorted(chosen & best) + sorted(chosen & second_best))[0:4]


def choose_cpus_from_best_cores(caches: list[int], cores: list[int]) -> list[int]:
    """Picks the cpus that the test must use.

    This variant gives up on cache discrimination and applies only the second level criteria:

    Collect up to 4 cpus by selecting, in that order:
    * cpus of non-hyperthreaded cores.
    * only one cpu of each hyperthreaded core.
    * any remaining cpu.

    Returns:
      A list of up to 4 vcpus. The ones at the head of the list are the best.
    """

    cpus_by_core = list(cores.values())  # What we get is a list of cpu groups.
    quality = 0
    report = defaultdict(lambda: 0)  # quality->count

    # Harvest the very top choice and remove it.
    chosen = [cpus[0] for cpus in cpus_by_core if len(cpus) == 1]
    cpus_by_core = [cpus for cpus in cpus_by_core if len(cpus) > 1]
    report[quality] += len(chosen)
    quality += 1

    # Collect the rest, one round at a time.
    while len(cpus_by_core) > 0 and len(chosen) < 4:
        other = ([cpus.pop(0) for cpus in cpus_by_core])
        cpus_by_core = [cpus for cpus in cpus_by_core if len(cpus) > 0]
        report[quality] += len(other)
        chosen.extend(other)
        quality = min(quality + 1, 2)

    logger.info("CPUs from best cores: "
                f"best={report[0]} second_best={report[1]} other={report[2]}")

    # The last round can get too many, so truncate to promised length.
    return chosen[0:4]


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

    Only br1a is executed and observed.

    Pretend traffic is injected by brload's. See the test cases for details.
    """

    router_cpus: list[int] = [0]
    brload_cpus: list[int] = [0]
    intfMap: dict[str, Intf] = {}

    ci = cli.Flag(
        "ci",
        help="Do extra checks for CI",
        envname="CI"
    )

    def init(self):
        """Collects information about vcpus/cores/caches layout."""

        super().init()
        self.choose_cpus()

    def choose_cpus(self):
        """Chooses 4 cpus and assigns 3 for the router and 1 for the blaster.

        Try various policies in decreasing order of preference. We use fewer than 4 cores
        only as a last resort
        """

        logger.info(f"CPUs summary BEGINS\n{cmd.lscpu('--extended')}\nCPUs summary ENDS")

        caches = defaultdict(list)  # cache -> [vcpu]
        cores = defaultdict(list)  # core -> [vcpu]

        all = json.loads(lscpu("-J", "--extended", "-b"))
        all_cpus = all.get("cpus")
        if all_cpus is None or len(all_cpus) == 0:
            logger.warn("Un-usable output from lscpu. Defaulting to using cpu0.")
            return

        for c in all_cpus:
            cpu = c.get("cpu")
            core = c.get("core")
            if cpu is None or core is None:
                logger.warn("Un-usable output from lscpu. Defaulting to using cpu0.")
                return

            l2 = core  # fall back to assuming one l2 per core.
            as_str = c.get("l1d:l1i:l2:l3")
            if as_str is not None:
                cache_info = as_str.split(":")
                if len(cache_info) >= 3:
                    as_str = cache_info[2]
                    l2 = int(as_str) if as_str.isdecimal() else 0

            caches[l2].append(cpu)
            cores[core].append(cpu)

        chosen = choose_cpus_from_unshared_cache(caches, cores)
        if len(chosen) < 4:
            chosen = choose_cpus_from_single_cache(caches, cores)
        if len(chosen) < 4:
            chosen = choose_cpus_from_best_cores(caches, cores)

        # Make the best of what we got. All but the last cpu go to the router. Those are the
        # best choice.
        if len(chosen) == 1:
            # When you have lemons...
            self.router_cpus = chosen
            self.brload_cpus = chosen
        else:
            self.router_cpus = chosen[:-1]
            self.brload_cpus = [chosen[-1]]

        logger.info(f"router cpus: {self.router_cpus}")
        logger.info(f"brload cpus: {self.brload_cpus}")

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
                   * A label by which brload identifies that interface.
                   * The IP address to be assigned to that interface.
                   * The IP address of one neighbor.
          ns: The network namespace where that interface must exist.

        """

        physlabel = req.label if req.exclusive == "true" else "mx"
        hostIntf = f"veth_{physlabel}_host"
        brIntf = f"veth_{physlabel}"

        # The interfaces
        # We do multiplex most requested br interfaces onto one physical interface pairs, so, we
        # must check that we haven't already created the physical pair.
        for i in self.intfMap.values():
            if i.name == hostIntf:
                peerMac = i.peerMac
                mac = i.mac
                break
        else:
            peerMac = mac_for_ip(req.peerIp)
            mac = mac_for_ip(req.ip)
            sudo("ip", "link", "add", hostIntf, "type", "veth", "peer", "name", brIntf)
            sudo("ip", "link", "set", hostIntf, "mtu", "8000")
            sudo("ip", "link", "set", brIntf, "mtu", "8000")
            sudo("sysctl", "-qw", f"net.ipv6.conf.{hostIntf}.disable_ipv6=1")
            sudo("ethtool", "-K", brIntf, "rx", "off", "tx", "off")
            sudo("ip", "link", "set", brIntf, "address", mac)

            # The network namespace
            sudo("ip", "link", "set", brIntf, "netns", ns)
            sudo("ip", "netns", "exec", ns,
                 "sysctl", "-qw", f"net.ipv6.conf.{brIntf}.disable_ipv6=1")

        # The addresses (presumably must be done once the br interface is in the namespace).
        sudo("ip", "netns", "exec", ns,
             "ip", "addr", "add", f"{req.ip}/{req.prefixLen}", "dev", brIntf)
        sudo("ip", "netns", "exec", ns,
             "ip", "neigh", "add", req.peerIp, "lladdr", peerMac, "nud", "permanent",
             "dev", brIntf)

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
               "-v", f"{self.artifacts}/conf:/etc/scion",
               "-d",
               "--network", "benchmark",
               "--publish", "9999:9090",
               "--name", "prometheus",
               "prom/prometheus:v2.47.2",
               "--config.file", "/etc/scion/prometheus.yml")

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
        brload = self.get_executable("brload")
        output = brload("show-interfaces")

        for line in output.splitlines():
            elems = line.split(",")
            if len(elems) != 5:
                continue
            t = IntfReq._make(elems)
            self.create_interface(t, "benchmark")

        # We don't need that symlink any more
        sudo("rm", "/var/run/netns/benchmark")

        # Now the router can start.
        docker("run",
               "-v", f"{self.artifacts}/conf:/etc/scion",
               "-d",
               "-e", "SCION_EXPERIMENTAL_BFD_DISABLE=true",
               "-e", "GOMAXPROCS=3",
               "--network", "container:prometheus",
               "--name", "router",
               "--cpuset-cpus", ",".join(map(str, self.router_cpus)),
               "scion/router:latest")

        time.sleep(2)

    def teardown(self):
        docker["logs", "router"].run_fg(retcode=None)
        docker("rm", "-f", "prometheus")
        docker("rm", "-f", "router")
        docker("network", "rm", "benchmark")  # veths are deleted automatically
        sudo("chown", "-R", whoami().strip(), self.artifacts)

    def exec_br_load(self, case: str, mapArgs: list[str], count: int) -> str:
        brload = self.get_executable("brload")
        # For num-streams, attempt to distribute uniformly on many possible number of cores.
        # 840 is a multiple of 1, 2, 3, 4, 5, 6, 7, 8, 10, 12, 14, 15, 20, 21, 24, 28, ...
        return sudo("taskset", "-c", ",".join(map(str, self.brload_cpus)),
                    brload.executable,
                    "run",
                    "--artifacts", self.artifacts,
                    *mapArgs,
                    "--case", case,
                    "--num-packets", str(count),
                    "--num-streams", "840")

    def run_test_case(self, case: str, mapArgs: list[str]) -> (int, int):
        logger.info(f"==> Starting load {case}")

        output = self.exec_br_load(case, mapArgs, 10000000)
        for line in output.splitlines():
            if line.startswith("metricsBegin"):
                _, beg, _, end = line.split()

        logger.info(f"==> Collecting {case} performance metrics...")

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
        conn = HTTPConnection("localhost:9999")
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
        conn = HTTPConnection("localhost:9999")
        conn.request("GET", f"/api/v1/query?{promQuery}")
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

        return processed, dropped

    # Fetch and log the number of cores used by Go. This may inform performance
    # modeling later.
    def log_core_counts(self):
        logger.info("==> Collecting number of cores...")
        promQuery = urlencode({
            'query': 'go_sched_maxprocs_threads{job="BR"}'
        })

        conn = HTTPConnection("localhost:9999")
        conn.request("GET", f"/api/v1/query?{promQuery}")
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f"Unexpected response: {resp.status} {resp.reason}")

        pld = json.loads(resp.read().decode("utf-8"))
        results = pld["data"]["result"]
        for result in results:
            instance = result["metric"]["instance"]
            _, val = result["value"]
            logger.info(f"Router Cores for {instance}: {int(val)}")

    def _run(self):
        # Build the interface mapping arg
        mapArgs = []
        for label, intf in self.intfMap.items():
            mapArgs.extend(["--interface", f"{label}={intf.name},{intf.mac},{intf.peerMac}"])

        # Run one test (30% size) as warm-up to trigger the frequency scaling, else the first test
        # gets much lower performance.
        self.exec_br_load(list(TEST_CASES)[0], mapArgs, 3000000)

        # At long last, run the tests
        rateMap = {}
        droppageMap = {}
        for testCase in TEST_CASES:
            processed, dropped = self.run_test_case(testCase, mapArgs)
            rateMap[testCase] = processed
            droppageMap[testCase] = dropped

        self.log_core_counts()

        # Log and check the performance...
        # If this is used as a CI test. Make sure that the performance is within the expected
        # ballpark.
        rateTooLow = []
        for tt, exp in TEST_CASES.items():
            if self.ci and exp != 0:
                logger.info(f"Packets/(machine*s) for {tt}: {rateMap[tt]} expected: {exp}")
                if rateMap[tt] < 0.8 * exp:
                    rateTooLow.append(tt)
            else:
                logger.info(f"Packets/(machine*s) for {tt}: {rateMap[tt]}")

        if len(rateTooLow) != 0:
            raise RuntimeError(f"Insufficient performance for: {rateTooLow}")

        # Log and check the saturation...
        # If this is used as a CI test. Make sure that the saturation is within the expected
        # ballpark: that should manifest some measurable amount of loss due to queue overflow.
        notSaturated = []
        for tt in TEST_CASES:
            total = rateMap[tt] + droppageMap[tt]
            if total == 0:
                logger.info(f"Droppage ratio unavailable for {tt}")
            else:
                ratio = float(droppageMap[tt]) / total
                exp = 0.03
                if self.ci:
                    logger.info(f"Droppage ratio for {tt}: {ratio:.1%} expected: {exp:.1%}")
                    if ratio < exp:
                        notSaturated.append(tt)
                else:
                    logger.info(f"Droppage ratio for {tt}: {ratio:.1%}")

        if len(notSaturated) != 0:
            raise RuntimeError(f"Insufficient saturation for: {notSaturated}")


if __name__ == "__main__":
    base.main(RouterBMTest)
