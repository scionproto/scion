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


"""Assertions for working with docker environments.

This module includes various assertions that can be used
as preconditions for tests that need to run in a specific
docker environment.

Assertions can be globally disabled by setting the
SCION_TESTING_DOCKER_ASSERTIONS_OFF environment variable to 1.
A warning message that assertions are off is printed to
the assertion's writer if a writer is specified.
"""

import json
import os
import subprocess
import sys
from typing import List, NamedTuple
from contextlib import redirect_stderr

import plumbum
from plumbum import cmd

SCION_DC_FILE = "gen/scion-dc.yml"
DC_PROJECT = "scion"
SCION_TESTING_DOCKER_ASSERTIONS_OFF = 'SCION_TESTING_DOCKER_ASSERTIONS_OFF'


def container_ip(container_name: str) -> str:
    """Returns the ip of the given container"""
    return cmd.docker("inspect", "-f", "{{range .NetworkSettings.Networks}}"
                      "{{.IPAddress}}{{end}}", container_name).rstrip()


class Compose(object):

    def __init__(self,
                 project: str = DC_PROJECT,
                 compose_file: str = SCION_DC_FILE):
        self.project = project
        self.compose_file = compose_file

    def __call__(self, *args, **kwargs) -> str:
        """Runs docker compose with the given arguments"""
        with redirect_stderr(sys.stdout):
            return cmd.docker_compose("-f", self.compose_file, "-p", self.project, *args, **kwargs)

    def collect_logs(self, out_dir: str = "logs/docker"):
        """Collects the logs from the services into the given directory"""
        out_p = plumbum.local.path(out_dir)
        cmd.mkdir("-p", out_p)
        for svc in self("config", "--services").splitlines():
            # Collect logs.
            dst_f = out_p / "%s.log" % svc
            with open(dst_f, "w") as log_file:
                cmd.docker.run(args=("logs", svc), stdout=log_file,
                               stderr=subprocess.STDOUT, retcode=None)
            # Collect coredupms.
            coredump_f = out_p / "%s.coredump" % svc
            try:
                cmd.docker.run(args=("cp", svc+":/share/coredump", coredump_f))
            except Exception:
                # If the coredump does not exist, do nothing.
                pass
            # Collect tshark traces.
            try:
                cmd.docker.run(args=("cp", svc+":/share/tshark", out_p))
                cmd.mv(out_p / "tshark" // "*", out_p)
                cmd.rmdir(out_p / "tshark")
            except Exception:
                # If there are no tshark captures, do nothing.
                pass


class _Network(NamedTuple):
    name: str
    driver: str
    containers: List[str]


class UnexpectedNetworkError(Exception):
    pass


def assert_no_networks(writer=None):
    """Raises an exception if unexpected docker networks are found.

    The default bridge, host and none networks are always ignored.

    If the SCION_TESTING_DOCKER_ASSERTIONS_OFF environmnent variable
    is set to 1, the assertion is not executed. A warning message
    is printed to the writer if the writer is set.

    Args:
        writer: If specified, the writer's write method is used to
            print detailed information about all unexpected networks
            before raising the exception.

    Raises:
        UnexpectedNetworkError: An unexpected network name was found. The
            message will contain the names of all unexepcted networks.
        plumbum.commands.processes.ProcessExecutionError: One of the docker
            commands returned a non-zero exit code.
    """
    if os.environ.get(SCION_TESTING_DOCKER_ASSERTIONS_OFF) == '1':
        if writer:
            writer.write("Docker networking assertions are OFF\n")
        return

    allowed_nets = ['bridge', 'host', 'none']
    unexpected_nets = []
    for net in _get_networks():
        if net.name not in allowed_nets:
            if writer:
                writer.write(f'{net.name} {net.driver} {net.containers}\n')
            unexpected_nets.append(net.name)
    if unexpected_nets:
        raise UnexpectedNetworkError(str(unexpected_nets))


def _get_networks() -> List[_Network]:
    """Gets information about existing docker networks.

    Returns:
        A slice containing one entry for each docker network.
        Default networks (e.g., bridge and host) are included.

    Raises:
        plumbum.commands.processes.ProcessExecutionError: One
            of the docker commands returns a non-zero exit code.
    """

    nets = []
    net_json = cmd.docker('network', 'ls', '-q', '--format={{json .}}')
    for net_json in net_json.splitlines():
        net = json.loads(net_json)
        net_inspect_json = cmd.docker('network', 'inspect',
                                      '--format={{json .}}', net['ID'])
        net_inspect = json.loads(net_inspect_json)

        containers = []
        for container_id, prop in net_inspect['Containers'].items():
            ipv4 = prop.get('IPv4Address', '')
            ipv6 = prop.get('IPv6Address', '')
            containers.append('%s: %s %s' % (prop['Name'], ipv4, ipv6))
        nets.append(_Network(net_inspect['Name'], net_inspect['Driver'],
                             containers))
    return nets
