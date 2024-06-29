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
import ssl
import time
import traceback

from benchmarklib import Intf, RouterBM
from collections import namedtuple
from plumbum import cli
from plumbum import cmd
from plumbum import local
from plumbum.cmd import docker
from plumbum.machines import LocalCommand
from random import randint
from urllib.request import urlopen

logger = logging.getLogger(__name__)

TEST_CASES = [
    "in",
    "out",
    "in_transit",
    "out_transit",
    "br_transit",
]

# Convenience types to carry interface params.
IntfReq = namedtuple("IntfReq", "label, prefix_len, ip, peer_ip, exclusive")


def sudo(*args: [str]) -> str:
    # -A, --askpass makes sure command is failing and does not wait for
    # interactive password input.
    return cmd.sudo("-A", *args)


class RouterBMTool(cli.Application, RouterBM):
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

    avail_interfaces: list[str] = []
    mx_interface: str = None
    to_flush: list[str] = []
    scrape_addr: str = None

    log_level = cli.SwitchAttr(["l", "loglevel"], str, default='warning', help="Logging level")

    doit = cli.Flag(["r", "run"],
                    help="Run the benchmark, as opposed to seeing the instructions.")
    json = cli.Flag(["j", "json"],
                    help="Output the report in json format.")

    # Used by the RouterBM mixin:
    coremark = cli.SwitchAttr(["c", "coremark"], int, default=0,
                              help="The coremark score of the subject machine.")
    mmbm = cli.SwitchAttr(["m", "mmbm"], int, default=0,
                          help="The mmbm score of the subject machine.")
    packet_size = cli.SwitchAttr(["s", "size"], int, default=172,
                                 help="Test packet size (includes all headers - floored at 154).")
    intf_map: dict[str, Intf] = {}
    brload: LocalCommand = local["./bin/brload"]
    brload_cpus: list[int] = []
    artifacts = f"{os.getcwd()}/acceptance/router_benchmark"
    prom_address: str = "localhost:9090"

    def host_interface(self, excl: bool):
        """Returns the next host interface that we should use for a brload links.

        If excl is true, we pick one and never pick that one again.
        Else, we pick one the first time it's needed and keep it for reuse.
        """
        if excl:
            return self.avail_interfaces.pop()

        if self.mx_interface is None:
            self.mx_interface = self.avail_interfaces.pop()

        return self.mx_interface

    def config_interface(self, req: IntfReq):
        """Configure an interfaces according to brload's requirements.

        The device must not be in use for anything else. The devices are picked from a list
        supplied by the user.

        We probably do not:
          sudo("ip", "addr", "add", f"{req.peer_ip}/{req.prefix_len}", "dev", host_intf)

        It causes trouble: if an IP is assigned, the kernel responds with "unbound port" icmp
        messages to the router traffic, which breaks the bound UDP connections that the router uses
        for external interfaces.

        Args:
          req: A requested router-side network interface. It comprises:
            * A label by which brload identifies that interface.
            * The IP address to be assigned to that interface.
            * The IP address of one neighbor.

        """
        exclusive = req.exclusive == "true"
        host_intf = self.host_interface(exclusive)

        # We need a means of connecting to the router's internal interface (from prometheus and
        # to scrape the horsepower microbenchmark results. We pick one address of
        # the router's subnet that's not otherwise used. This must NOT be "PeerIP".
        # brload requires the internal interface to be "exclusive", that's our clue.
        if exclusive:
            net = ipaddress.ip_network(f"{req.ip}/{req.prefix_len}", strict=False)
            hostAddr = next(net.hosts()) + 126
            self.scrape_addr = req.ip
            sudo("ip", "addr", "add", f"{hostAddr}/{req.prefix_len}",
                 "broadcast", str(net.broadcast_address), "dev", host_intf)
            self.to_flush.append(host_intf)

        logger.debug(f"=> Configuring interface {host_intf} for: {req}...")

        # We do multiplex most requested router interfaces onto one physical interface, so, we
        # must check that we haven't already configured the physical one.
        for i in self.intf_map.values():
            if i.name == host_intf:
                break
        else:
            sudo("ip", "link", "set", host_intf, "mtu", "9000")

            # Do not assign the host addresses but create one link-local addr.
            # Brload needs some src IP to send arp requests. (This requires rp_filter
            # to be off on the router side, else, brload's arp requests are discarded).
            sudo("ip", "addr", "add", f"169.254.{randint(0, 255)}.{randint(0, 255)}/16",
                 "broadcast", "169.254.255.255",
                 "dev", host_intf, "scope", "link")
            sudo("sysctl", "-qw", f"net.ipv6.conf.{host_intf}.disable_ipv6=1")
            self.to_flush.append(host_intf)

        # Fit for duty.
        sudo("ip", "link", "set", host_intf, "up")

        # Ship it. Leave mac addresses alone. In this standalone test we use the real one.
        self.intf_map[req.label] = Intf(host_intf, None, None)

    def fetch_horsepower(self) -> tuple[int]:
        try:
            url = f"https://{self.scrape_addr}/horsepower.json"
            resp = urlopen(url, context=ssl._create_unverified_context())
            hp = json.loads(resp.read().decode("ascii"))
        except Exception as e:
            logger.warning(f"Fetching coremark and mmbm from {url}... {e}")
            return

        if self.coremark == 0:
            self.coremark = round(hp["coremark"])

        if self.mmbm == 0:
            self.mmbm = round(hp["mmbm"])

    def setup(self, avail_interfaces: list[str]):
        logger.info("Preparing...")

        # Check that the given interfaces are safe to use. We will wreck their config.
        for intf in avail_interfaces:
            output = sudo("ip", "addr", "show", "dev", intf)
            if len(output.splitlines()) > 2:
                logger.error(f"""\
                Interface {intf} appears to be in some kind of use. Cowardly refusing to modify it.
                If you have a network manager, tell it to disable or ignore that interface.
                Else, how about \"sudo ip addr flush dev {intf}\"?
                """)
                raise RuntimeError("Interface in use")

        # Looks safe.
        self.avail_interfaces = avail_interfaces

        # Run test brload test with --show-interfaces and set up the interfaces as it says.
        # We supply the label->host-side-name mapping to brload when we start it.
        logger.debug("==> Configuring host interfaces...")

        output = self.brload("show-interfaces")

        lines = sorted(output.splitlines())
        for line in lines:
            elems = line.split(",")
            if len(elems) != 5:
                continue
            logger.debug(f"Requested by brload: {line}")
            t = IntfReq._make(elems)
            self.config_interface(t)

        # Start an instance of prometheus configured to scrape the router.
        logger.debug("==> Starting prometheus...")
        docker("run",
               "-v", f"{self.artifacts}/conf:/etc/scion",
               "-d",
               "--network", "host",
               "--name", "prometheus_bm",
               "prom/prometheus:v2.47.2",
               "--config.file", "/etc/scion/prometheus.yml")

        time.sleep(2)

        # Collect the horsepower microbenchmark numbers if we can.
        # They'll be used to produce a performance index.
        self.fetch_horsepower()

        logger.info("Prepared")

    def cleanup(self, retcode: int):
        docker("rm", "-f", "prometheus_bm")
        for intf in self.to_flush:
            sudo("ip", "addr", "flush", "dev", intf)
        return retcode

    def instructions(self):
        output = self.brload("show-interfaces")

        exclusives = []
        multiplexed = []
        reqs = []
        intf_index = 0

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
            self.avail_interfaces.append(str(intf_index))  # Use numbers as placeholders
            intf_index += 1

        # TODO: Because of multiplexing, there are fewer real interfaces than labels requested
        # by brload. So, not all placeholders get used (fine) and it happens that the low indices
        # are the ones not used (confusing for the user). Currently we end-up with 1 and 2
        # (and no 0), which is acceptable but fortuitous.
        for req in reqs:
            e = req.exclusive == "true"
            a = f"{req.ip}/{req.prefix_len}"
            i = self.host_interface(e)
            if e:
                exclusives.append(f"{a} (must reach: #{i})")
            else:
                multiplexed.append(f"{a} (must reach: #{i})")
        nl = "\n"
        print(f"""
INSTRUCTIONS:

1 - Configure your subject router according to accept/router_benchmark/conf/router.toml")
    If using openwrt, an easy way to do that is to install the bmtools.ipk package. In addition,
    bmtools includes two microbenchmarks: scion-coremark and scion-mmbm. Those will run
    automatically and the results will be used to improve the benchmark report.

    Optional: If you did not install bmtools.ipk, install and run those microbenchmarks and make a
    note of the results: (scion-coremark; scion-mmbm).

2 - Configure the following interfaces on your router (The procedure depends on your router
    UI) - All interfaces should have the mtu set to 9000:
    - One physical interface with addresses: {", ".join(multiplexed)}
{nl.join(['    - One physical interface with address: ' + s for s in exclusives])}

    IMPORTANT: if you're using a partitioned network (eg. multiple switches or no switches),
    the "must reach" annotation matters. The '#' number is the order in which the corresponding host
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

    If coremak and mmbm values are available, the report will include a performance index.

    If coremark and mmbm are not available from the test subject, you may supply them on the command
    line. To that end, add the following arguments: "--coremark=<coremark>", "--mmbm=<mmbm>", where
    <coremark> and <mmbm> are the results you optionally collected in step 1.

8 - Be patient...

9 - Read the report.
""")

    def main(self, *interfaces: str):
        status = 1
        try:
            logging.basicConfig(level=self.log_level.upper())
            if not self.doit:
                self.instructions()
                status = 0
            else:
                self.setup(list(interfaces))
                results = self.run_bm(TEST_CASES)
                # No CI_check. We have no particular expectations here.
                # Output the performance in human-friendly form by default...
                if self.json:
                    print(results.as_json())
                else:
                    print(results.as_report())
                status = 0
        except KeyboardInterrupt:
            logger.info("Bailing out...")
        except Exception:
            logger.error(traceback.format_exc())
        except SystemExit:
            pass
        return status


if __name__ == "__main__":
    RouterBMTool()
