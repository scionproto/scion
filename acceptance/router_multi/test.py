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
from plumbum import cmd

from acceptance.common import base

import logging

logger = logging.getLogger(__name__)


def exec_docker(command: str) -> str:
    return cmd.docker(str.split(command))


def sudo(command: str) -> str:
    # -A, --askpass makes sure command is failing and does not wait for
    # interactive password input.
    return cmd.sudo("-A", str.split(command))


def create_veth(host: str, container: str, ip: str, mac: str, ns: str, neighbors: List[str]):
    sudo("ip link add %s mtu 8000 type veth peer name %s mtu 8000" % (host, container))
    sudo("sysctl -qw net.ipv6.conf.%s.disable_ipv6=1" % host)
    sudo("ip link set %s up" % host)
    sudo("ip link set %s netns %s" % (container, ns))
    sudo("ip netns exec %s sysctl -qw net.ipv6.conf.%s.disable_ipv6=1" % (ns, container))
    sudo("ip netns exec %s ethtool -K %s rx off tx off" % (ns, container))
    sudo("ip netns exec %s ip link set %s address %s" % (ns, container, mac))
    sudo("ip netns exec %s ip addr add %s dev %s" % (ns, ip, container))
    for n in neighbors:
        sudo("ip netns exec %s ip neigh add %s lladdr f0:0d:ca:fe:be:ef nud permanent dev %s"
             % (ns, n, container))
    sudo("ip netns exec %s ip link set %s up" % (ns, container))


class RouterTest(base.TestBase):
    """
    Tests that the implementation of a router pass a number of test case where we
    feed the router an crafted packet and we expect them to route then accordingly.

    This test depends on an image called pause. This image is very thin, 250KB,
    and is used to keep the network namespace open during the test. It is
    stored locally by executing `docker save kubernetes/pause > pause.tar`. It
    can be replaced at any time with any other image e.g. Alpine.
    """

    pause_tar = cli.SwitchAttr(
        "pause_tar",
        str,
        help="taball with the pause image",
    )

    bfd = cli.Flag(
        "bfd",
        help="use BFD",
    )

    def setup_prepare(self):
        super().setup_prepare()

        shutil.copytree("acceptance/router_multi/conf/", self.artifacts / "conf")
        sudo("mkdir -p /var/run/netns")

        pause_image = exec_docker("image load -q -i %s" % self.pause_tar).rsplit(' ', 1)[1]
        exec_docker("run -d --network=none --name pause %s" % pause_image)
        ns = exec_docker("inspect pause -f '{{.NetworkSettings.SandboxKey}}'").replace("'", "")

        sudo("ln -sfT %s /var/run/netns/pause" % ns)
        self.create_veths("pause")

        sudo("rm /var/run/netns/pause")

    def setup_start(self):
        super().setup_start()

        if self.bfd:
            exec_docker(f"run -v {self.artifacts}/conf:/etc/scion -d "
                        "--network container:pause --name router "
                        "scion/router:latest")
        else:
            exec_docker(f"run -v {self.artifacts}/conf:/etc/scion -d "
                        "--network container:pause --name router "
                        "scion/router:latest "
                        "--config /etc/scion/router_nobfd.toml")
        time.sleep(1)

    def _run(self):
        braccept = self.get_executable("braccept")
        bfd_arg = ""
        if self.bfd:
            bfd_arg = "--bfd"
        sudo("%s --artifacts %s %s" % (braccept.executable, self.artifacts, bfd_arg))

    def teardown(self):
        cmd.docker["logs", "router"].run_fg(retcode=None)
        exec_docker("rm -f router")
        exec_docker("rm -f pause")  # veths are deleted automatically
        sudo("chown -R %s %s" % (cmd.whoami(), self.artifacts))

    def create_veths(self, ns: str):
        # Set default TTL for outgoing packets to the common value 64, so that packets sent
        # from router will match the expected value.
        sudo("ip netns exec %s sysctl -w net.ipv4.ip_default_ttl=64" % ns)

        create_veth("veth_int_host", "veth_int", "192.168.0.11/24", "f0:0d:ca:fe:00:01", ns,
                    ["192.168.0.12", "192.168.0.13", "192.168.0.14", "192.168.0.51", "192.168.0.61",
                        "192.168.0.71"])
        create_veth("veth_121_host", "veth_121", "192.168.12.2/31", "f0:0d:ca:fe:00:12", ns,
                    ["192.168.12.3"])
        create_veth("veth_131_host", "veth_131", "192.168.13.2/31", "f0:0d:ca:fe:00:13", ns,
                    ["192.168.13.3"])
        create_veth("veth_141_host", "veth_141", "192.168.14.2/31", "f0:0d:ca:fe:00:14", ns,
                    ["192.168.14.3"])
        create_veth("veth_151_host", "veth_151", "192.168.15.2/31", "f0:0d:ca:fe:00:15", ns,
                    ["192.168.15.3"])


if __name__ == "__main__":
    base.main(RouterTest)
