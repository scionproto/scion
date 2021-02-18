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


import os
import argparse
import shutil
import time

from typing import List
from plumbum import cmd


def docker(command: str) -> str:
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


class RouterTest:
    """
    Tests that the implementation of a router pass a number of test case where we
    feed the router an crafted packet and we expect them to route then accordingly.

    This test depends on an image called pause. This image is very thin, 250KB,
    and is used to keep the network namespace open during the test. It is
    stored locally by executing `docker save kubernetes/pause > pause.tar`. It
    can be replaced at any time with any other image e.g. Alpine.
    """

    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--braccept_bin', dest='bin')
        parser.add_argument('--conf_dir', dest='conf')
        parser.add_argument('--image_tar', dest='image')
        parser.add_argument('--pause_tar', dest='pause')
        args = parser.parse_args()

        self.bin = args.bin
        self.image_tar = args.image
        self.pause_tar = args.pause
        self.artifacts = "/tmp/artifacts-scion"
        if 'TEST_UNDECLARED_OUTPUTS_DIR' in os.environ:
            self.artifacts = os.environ['TEST_UNDECLARED_OUTPUTS_DIR']
        shutil.copytree(args.conf, self.artifacts + "/conf")
        sudo("mkdir -p /var/run/netns")

    def main(self):
        try:
            self.setup()
            self.run_tests()
        finally:
            self.teardown()

    def setup(self):
        self.pause_image = docker("image load -q -i %s" % self.pause_tar).rsplit(' ', 1)[1]
        self.router_image = docker("image load -q -i %s" % self.image_tar).rsplit(' ', 1)[1]
        print(docker("images"))

        self.pause = docker("run -d --network=none --name pause %s" % self.pause_image)
        ns = docker("inspect %s -f '{{.NetworkSettings.SandboxKey}}'" % self.pause).replace("'", "")

        sudo("ln -sfT %s /var/run/netns/pause" % ns)
        self.create_veths("pause")

        print("# Host Network Stack")
        print(sudo("ip a"))
        print("# Container Network Stack")
        print(sudo("ip netns exec pause ip a"))

        sudo("rm /var/run/netns/pause")

    def run(self, bfd: bool, bin: str, args: str = "", wait: int = 0):
        envs = ["-e  SCION_EXPERIMENTAL_BFD_DISABLE=true",
                "-e SCION_EXPERIMENTAL_DISABLE_SERVICE_HEALTH=\"\""]
        bfd_arg = ""

        if bfd:
            envs = ["-e SCION_EXPERIMENTAL_DISABLE_SERVICE_HEALTH=\"\""]
            bfd_arg = "--bfd"

        try:
            router = docker("run -v %s/conf:/share/conf -d %s %s --network container:%s \
                            --name router %s" % (self.artifacts, " ".join(envs), args,
                            self.pause, self.router_image))[0:11]
            time.sleep(wait)
            sudo("%s --artifacts %s %s" % (bin, self.artifacts, bfd_arg))
        finally:
            print("# Router logs")
            _, _, s = cmd.docker["logs", router].run()
            print(str(s))
            docker("stop %s" % router)
            docker("rm %s" % router)

    def run_tests(self):
        self.run(bfd=False, bin=self.bin)
        self.run(bfd=True, bin=self.bin)

    def teardown(self):
        docker("stop %s" % self.pause)
        docker("rm %s" % self.pause)  # veths are deleted automatically
        docker("rmi %s %s" % (self.router_image, self.pause_image))
        sudo("chown -R %s %s" % (cmd.whoami(), self.artifacts))

    def create_veths(self, ns: str):
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
    RouterTest().main()
