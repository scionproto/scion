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
import re
import subprocess
from typing import List, NamedTuple

import plumbum
from plumbum import cmd

SCION_DC_FILE = "gen/scion-dc.yml"
DC_PROJECT = "scion"
SCION_TESTING_DOCKER_ASSERTIONS_OFF = 'SCION_TESTING_DOCKER_ASSERTIONS_OFF'


class Compose(object):
    def __init__(self,
                 project: str = DC_PROJECT,
                 compose_file: str = SCION_DC_FILE):
        self.project = project
        self.compose_file = compose_file

    def __call__(self, *args, **kwargs) -> str:
        """Runs docker compose with the given arguments"""
        # Note: not using plumbum here due to complications with encodings in the captured output
        try:
            res = subprocess.run(
                ["docker-compose", "-f", self.compose_file, "-p", self.project, *args],
                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        except subprocess.CalledProcessError as e:
            raise _CalledProcessErrorWithOutput(e) from None
        return res.stdout

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

    def start_container(self, container):
        """Starts the container with the specified name.

        Args:
            container: the name of the container.
        """
        print(self("start", container))

    def restart_container(self, container):
        """Restarts the container with the specified name.

        Args:
            container: the name of the container.
        """
        print(self("restart", container))

    def stop_container(self, container):
        """Stops the container with specified name.

        Args:
            container: the name of the container.
        """
        print(self("stop", container))

    def list_containers(self, container_pattern: str) -> List[str]:
        """Lists all containers that match the given pattern.

        Args:
            container_pattern: A regex string to match the container. The regex
              format is standard Python regex format.

        Returns:
            A list of strings with the container names that match the
            container_pattern regex.
        """
        containers = self("config", "--services")
        matching_containers = []
        for container in containers.splitlines():
            if re.match(container_pattern, container):
                matching_containers.append(container)
        return matching_containers

    def send_signal(self, container, signal):
        """Sends signal to the container with the specified name.

        Args:
            container: the name of the container.
            signal: the signal to send
        """
        print(self("kill", "-s", signal, container))

    def execute(self, container, *args, **kwargs):
        """Executes an arbitrary command in the specified container.

        There's one minute timeout on the command so that tests don't get stuck.

        Args:
            container: the name of the container to execute the command in.

        Returns:
            The output of the command.
        """
        user = kwargs.get("user", "{}:{}".format(os.getuid(), os.getgid()))
        return self("exec", "-T", "--user", user, container,
                    "timeout", "1m", *args, **kwargs)

    def execute_as_user(self, container, user, *args, **kwargs):
        """Executes an arbitrary command in the specified container.

        There's one minute timeout on the command so that tests don't get stuck.

        Args:
            container: the name of the container to execute the command in.
            user: the user to use to execute the command

        Returns:
            The output of the command.
        """
        return self("exec", "-T", "--user", user, container,
                    "timeout", "1m", *args)


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


class _CalledProcessErrorWithOutput(Exception):
    def __init__(self, base):
        self.base = base

    def __str__(self):
        return "%s\nSTDOUT:\n%s\nSTDERR:%s\n" % (str(self.base), self.base.stdout, self.base.stderr)
