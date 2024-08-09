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
import shutil
import time
import os

from acceptance.common import base
from benchmarklib import Intf, RouterBM
from collections import defaultdict, namedtuple
from plumbum import cli
from plumbum import cmd
from plumbum.cmd import docker, whoami, lscpu, taskset
from plumbum.machines import LocalCommand
from random import randint

logger = logging.getLogger(__name__)

# Default packet length for CI testing
BM_PACKET_SIZE = 1500

# Router profiling ON or OFF?
PROFILING = False

# Those values are valid expectations only when running in the CI environment.
TEST_CASES = {
    "in": 720000,
    "out": 730000,
    "in_transit": 700000,
    "out_transit": 720000,
    "br_transit": 720000,
}

# Convenience types to carry interface request params.
IntfReq = namedtuple("IntfReq", "label, prefix_len, ip, peer_ip, exclusive")


def sudo(*args: [str]) -> str:
    # -A, --askpass makes sure command is failing and does not wait for
    # interactive password input.
    return cmd.sudo("-A", *args)


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


class RouterBMTest(base.TestBase, RouterBM):
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

    # TODO(jiceatscion): We construct intf_map during setup and we use it later, during
    # _run(). As a result, running setup, run, at teardown separately is not possible for
    # this test. May be it would be possible to reconstruct the map without actually setup the
    # interfaces, assuming brload isn't being changed in-between.

    router_cpus: list[int] = [0]

    # Used by the RouterBM mixin:
    coremark: int = 0
    mmbm: int = 0
    packet_size: int = BM_PACKET_SIZE
    intf_map: dict[str, Intf] = {}
    brload: LocalCommand = None
    brload_cpus: list[int] = [0]
    prom_address: str = "localhost:9999"

    ci = cli.Flag(
        "ci",
        help="Do extra checks for CI",
        envname="CI"
    )

    def init(self):
        """Collects information about vcpus/cores/caches layout."""

        super().init()
        self.brload = self.get_executable("brload")
        self.choose_cpus()

    def choose_cpus(self):
        """Chooses 4 cpus and assigns 3 for the router and 1 for the blaster.

        Try various policies in decreasing order of preference. We use fewer than 4 cores
        only as a last resort
        """

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
            self.brload_cpus = chosen[-1:]

        logger.info(f"router cpus: {self.router_cpus}")
        logger.info(f"brload cpus: {self.brload_cpus}")

    def create_interface(self, req: IntfReq, ns: str):
        """Creates a pair of virtual interfaces, with one end in the given network namespace and the
        other in the host stack.

        The outcome is the pair of interfaces and a record in intf_map, which associates the given
        label with the network interface's host-side name and two mac addresses; one for each end
        of the pair. The mac addresses, if they can be chosen, are not chosen by the invoker, but
        by this function. When we can choose, we follow a convention to facilitate debugging.
        Otherwise the values don't matter. brload has no expectations.

        We do not:
          sudo("ip", "addr", "add", f"{req.peer_ip}/{req.prefix_len}", "dev", hostIntf)

        It causes trouble: if an IP is assigned, the kernel responds with "unbound port" icmp
        messages to the router traffic, which breaks the bound UDP connections that the router uses
        for external interfaces.

        We do not:
          sudo("ip", "netns", "exec", ns, "ip", "neigh", "add", req.peer_ip,
               "lladdr", peer_mac, "nud", "permanent", "dev", brIntf)

        This isn't need because brload now responds to arp requests.

        We do not:
          sudo("ip", "link", "set", hostIntf, "address", peer_mac)

        If we do that, the interface address matches the dst addr in router->brload packets. This
        might seem desirable, even necessary, but is neither: since we're using veth pairs, the
        packets arrive regardless of address. However, if the address matches the one assigned then
        the kernel processes the packets in some way and the overall performance is reduced by 50%!
        When dealing with real NICs, brload uses the real mac addr. In this test, we tell it what to
        use.

        Args:
          req: A requested router-side network interface. It comprises:
            * A label by which brload identifies that interface.
            * The IP address to be assigned to that interface.
            * The IP address of one neighbor.
          ns: The network namespace where that interface must exist.

        """

        phys_label = req.label if req.exclusive == "true" else "mx"
        host_intf = f"veth_{phys_label}_host"
        br_intf = f"veth_{phys_label}"

        # We do multiplex most requested router interfaces onto one physical interface pairs, so, we
        # must check that we haven't already created the physical pair.
        for i in self.intf_map.values():
            if i.name == host_intf:
                peer_mac = i.peer_mac
                mac = i.mac
                break
        else:
            peer_mac = mac_for_ip(req.peer_ip)
            mac = mac_for_ip(req.ip)
            sudo("ip", "link", "add", host_intf, "type", "veth", "peer", "name", br_intf)
            sudo("ip", "link", "set", host_intf, "mtu", "9000")
            sudo("ip", "link", "set", host_intf, "arp", "off")  # Make sure the real addr isn't used

            # Do not assign the host addresses but create one link-local addr.
            # Brload needs some src IP to send arp requests.
            sudo("ip", "addr", "add", f"169.254.{randint(0, 255)}.{randint(0, 255)}/16",
                 "broadcast", "169.254.255.255",
                 "dev", host_intf, "scope", "link")

            sudo("sysctl", "-qw", f"net.ipv6.conf.{host_intf}.disable_ipv6=1")
            sudo("ethtool", "-K", br_intf, "rx", "off", "tx", "off")
            sudo("ip", "link", "set", br_intf, "mtu", "9000")
            sudo("ip", "link", "set", br_intf, "address", mac)

            # The network namespace
            sudo("ip", "link", "set", br_intf, "netns", ns)
            sudo("ip", "netns", "exec", ns,
                 "sysctl", "-qw", f"net.ipv6.conf.{br_intf}.disable_ipv6=1")
            sudo("ip", "netns", "exec", ns,
                 "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
            sudo("ip", "netns", "exec", ns,
                 "sysctl", "-qw", f"net.ipv4.conf.{br_intf}.rp_filter=0")

        # Add the router side IP addresses (even if we're multiplexing on an existing interface).
        sudo("ip", "netns", "exec", ns,
             "ip", "addr", "add", f"{req.ip}/{req.prefix_len}",
             "broadcast",
             ipaddress.ip_network(f"{req.ip}/{req.prefix_len}", strict=False).broadcast_address,
             "dev", br_intf)

        # Fit for duty.
        sudo("ip", "link", "set", host_intf, "up")
        sudo("ip", "netns", "exec", ns, "ip", "link", "set", br_intf, "up")

        # Ship it.
        self.intf_map[req.label] = Intf(host_intf, mac, peer_mac)

        # If that's an exclusive interface pair, we can use it to profile the router:
        if req.exclusive == "true":
            self.profiling_addr = req.ip

    def fetch_horsepower(self):
        try:
            coremark_exe = self.get_executable("coremark")
            output = taskset("-c", self.router_cpus[0], coremark_exe.executable)
            line = output.splitlines()[-1]
            if line.startswith("CoreMark "):
                elems = line.split(" ")
                if len(elems) >= 4:
                    self.coremark = round(float(elems[3]))
        except Exception as e:
            logger.info(e)

        try:
            mmbm_exe = self.get_executable("mmbm")
            output = taskset("-c", self.router_cpus[0], mmbm_exe.executable)
            for line in output.splitlines():
                if line.startswith("\"mmbm\": "):
                    elems = line.strip(",").split(" ")
                    if len(elems) >= 2:
                        self.mmbm = round(float(elems[1]))
                    break
        except Exception as e:
            logger.info(e)

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
        output = self.brload("show-interfaces")

        for line in output.splitlines():
            elems = line.split(",")
            if len(elems) != 5:
                continue
            t = IntfReq._make(elems)
            self.create_interface(t, "benchmark")

        # Now the router can start.
        docker("run",
               "-v", f"{self.artifacts}/conf:/etc/scion",
               "-d",
               "-e", f"GOMAXPROCS={len(self.router_cpus)}",
               "--network", "container:prometheus",
               "--name", "router",
               "--cpuset-cpus", ",".join(map(str, self.router_cpus)),
               "scion/router:latest")

        time.sleep(2)

        # Collect the horsepower microbenchmark numbers if we can.
        # They'll be used to produce a performance index.
        self.fetch_horsepower()

        # Optionally profile the router
        if PROFILING:
            docker("run",
                   "--rm",
                   "-d",
                   "-u", os.getuid(),
                   "-v", f"{self.artifacts}:/out",
                   "--network", "container:prometheus",
                   "curlimages/curl",
                   f"{self.profiling_addr}:30442/debug/pprof/profile?seconds=70",
                   "-o", "/out/cpu.pprof")

        # We don't need that symlink any more
        sudo("rm", "/var/run/netns/benchmark")

    def teardown(self):
        docker["logs", "router"].run_fg(retcode=None)
        docker("rm", "-f", "prometheus")
        docker("rm", "-f", "router")
        docker("network", "rm", "benchmark")  # veths are deleted automatically
        sudo("chown", "-R", whoami().strip(), self.artifacts)

    def _run(self):
        results = self.run_bm(list(TEST_CASES.keys()))
        if results.cores != len(self.router_cpus):
            raise RuntimeError("Wrong number of cores used by the router; "
                               f"planned: {len(self.router_cpus)}), observed: {results.cores}")

        if self.ci:
            results.CI_check(TEST_CASES)

        # Output results as json for easier post-processing
        logger.info(results.as_json())

        if self.ci:
            if results.failed:
                raise RuntimeError("CI check failed")


if __name__ == "__main__":
    base.main(RouterBMTest)
