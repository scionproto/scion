# Copyright 2019 Anapaya Systems
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
import os
import subprocess
import re
from typing import List
from typing import Type

from plumbum import cli
from plumbum import local
from plumbum import cmd
from plumbum import path

from acceptance.common.docker import Compose
from acceptance.common.log import LogExec
from acceptance.common.scion import SCION

NAME = "NOT_SET"  # must be set by users of the Base class.
DIR = "NOT_SET"
logger = logging.getLogger(__name__)


def set_name(file: str):
    global NAME
    global DIR
    DIR = local.path(file).dirname.name
    NAME = DIR[:-len("_acceptance")]


class TestState:
    """
    TestState is used to share state between the command
    and the sub-command.
    """

    artifacts = None

    def __init__(self, scion: SCION, dc: Compose):
        """
        Create new environment state for an execution of the acceptance
        testing framework. Plumbum subcommands can access this state
        via the parent to retrieve information about the test environment.
        """

        self.scion = scion
        self.dc = dc
        self.setup_params = []
        self.executables = []
        self.topo = ""
        self.containers_tar = ""
        if "TEST_UNDECLARED_OUTPUTS_DIR" in os.environ:
            self.artifacts = local.path(
                os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
        else:
            self.artifacts = local.path("/tmp/artifacts-scion")
        self.dc.compose_file = self.artifacts / "gen/scion-dc.yml"
        self.no_docker = False
        self.tools_dc = local["./tools/dc"]

    def executable(self, name: str) -> str:
        """Resolve the executable by name.

        If the executable is not in the executables mapping, the return value
        is './bin/<name>'
        """
        for pair in self.executables:
            executable_name, path = pair.split(":")
            if executable_name == name:
                return os.path.abspath(path)
        return "./bin/"+name


class TestBase(cli.Application):
    """
    TestBase is used to implement the test entry point. Tests should
    sub-class it and only define the doc string.
    """
    test_state = None  # type: TestState

    @cli.switch("setup-params", str, help="Additional setup parameters")
    def set_params(self, params: str):
        self.test_state.setup_params = params.split()

    @cli.switch("executables", str, list=True)
    def executables(self, executables):
        self.test_state.executables = executables

    @cli.switch("topo", str)
    def topo(self, topo):
        self.test_state.topo = topo

    @cli.switch("artifacts",
                str,
                envname="ACCEPTANCE_ARTIFACTS",
                help="Artifacts directory (for legacy tests)")
    def artifacts_dir(self, a_dir: str):
        self.test_state.artifacts = local.path("%s/%s/" % (a_dir, NAME))

    @cli.switch("artifacts_dir",
                str,
                help="Artifacts directory (for bazel tests)")
    def artifacts_dir_new(self, a_dir: str):
        self.test_state.artifacts = local.path(a_dir)
        self.test_state.dc.compose_file = self.test_state.artifacts / "gen/scion-dc.yml"

    @cli.switch("containers_tar", str, help="The tarball with the containers")
    def containers_tar(self, tar: str):
        self.test_state.containers_tar = tar

    @cli.switch("bazel_rule",
                str,
                help="The bazel rule that triggered the test")
    def test_type(self, rule: str):
        self.test_state.bazel_rule = rule

    def setup(self):
        self.setup_prepare()
        self.setup_start()

    def setup_prepare(self):
        """Unpacks loads local docker images and generates the topology.
        """
        # Delete old artifacts, if any.
        cmd.rm("-rf", self.test_state.artifacts)
        cmd.mkdir(self.test_state.artifacts)
        print("artifacts dir: %s" % self.test_state.artifacts)
        print(cmd.docker("image", "load", "-i",
                         self.test_state.containers_tar))
        # Define where coredumps will be stored.
        print(
            cmd.docker("run", "--rm", "--privileged", "alpine", "sysctl", "-w",
                       "kernel.core_pattern=/share/coredump"))
        self._setup_generate()

    def _setup_generate(self):
        """Generate the topology"""
        def copy_file(src, dst):
            subprocess.run(["mkdir", "-p", os.path.dirname(dst)], check=True)
            subprocess.run(["cp", "-L", src, dst], check=True)

        cryptolib = self.test_state.artifacts + "/crypto_lib.sh"
        copy_file(
            self.test_state.executable("crypto_lib.sh"),
            cryptolib,
        )
        copy_file(
            self.test_state.topo,
            self.test_state.artifacts + "/topology.json",
        )
        copy_file(
            "tools/docker-ip",
            self.test_state.artifacts + "/tools/docker-ip",
        )

        env = os.environ.copy()
        spki_path = os.path.dirname(self.test_state.executable("scion-pki"))
        env["PATH"] = spki_path + ":" + env["PATH"]
        env["CRYPTOLIB"] = cryptolib
        subprocess.run(
            [
                self.test_state.executable("topogen"),
                "-o=" + self.test_state.artifacts + "/gen",
                "-c=topology.json",
                "-d",
                *self.test_state.setup_params,
            ],
            check=True,
            env=env,
            cwd=self.test_state.artifacts,
        )
        for support_dir in ["logs", "gen-cache", "gen-data", "traces"]:
            os.makedirs(self.test_state.artifacts + "/" + support_dir,
                        exist_ok=True)

    def setup_start(self):
        """Starts the docker containers in the topology.
        """
        print(self.test_state.dc("up", "-d"))
        print(self.test_state.dc("ps"))

    def teardown(self):
        out_dir = self.test_state.artifacts / "logs"
        self.test_state.dc.collect_logs(out_dir=out_dir)
        ps = self.test_state.dc("ps")
        print(self.test_state.dc("down", "-v"))
        if re.search(r"Exit\s+[1-9]\d*", ps):
            raise Exception("Failed services.\n" + ps)

    def start_container(self, container):
        """Starts the container with the specified name.

        Args:
            container: the name of the container.
        """
        print(self.test_state.dc("start", container))

    def stop_container(self, container):
        """Stops the container with specified name.

        Args:
            container: the name of the container.
        """
        print(self.test_state.dc("stop", container))

    def list_containers(self, container_pattern: str) -> List[str]:
        """Lists all containers that match the given pattern.

        Args:
            container_pattern: A regex string to match the container. The regex
              format is standard Python regex format.

        Returns:
            A list of strings with the container names that match the
            container_pattern regex.
        """
        containers = self.test_state.dc("config", "--services")
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
        print(self.test_state.dc("kill", "-s", signal, container))

    def execute(self, container, *args, **kwargs):
        """Executes an arbitrary command in the specified container.

        There's one minute timeout on the command so that tests don't get stuck.

        Args:
            container: the name of the container to execute the command in.

        Returns:
            The output of the command.
        """
        user = kwargs.get("user", "{}:{}".format(os.getuid(), os.getgid()))
        return self.test_state.dc("exec", "-T", "--user", user, container,
                                  "timeout", "1m", *args)


class CmdBase(cli.Application):
    """ CmdBase is used to implement the test sub-commands. """
    tools_dc = local["./tools/dc"]

    def cmd_dc(self, *args):
        for line in self.dc(*args).splitlines():
            print(line)

    def cmd_setup(self):
        cmd.mkdir("-p", self.artifacts)

    def cmd_teardown(self):
        if not self.no_docker:
            self.dc.collect_logs(self.artifacts / "logs" / "docker")
            self.tools_dc("down")
        self.scion.stop()

    def _collect_logs(self, name: str):
        if path.local.LocalPath("gen/%s-dc.yml" % name).exists():
            self.tools_dc("collect_logs", name,
                          self.artifacts / "logs" / "docker")

    def _teardown(self, name: str):
        if path.local.LocalPath("gen/%s-dc.yml" % name).exists():
            self.tools_dc(name, "down")

    @staticmethod
    def test_dir(prefix: str = "",
                 directory: str = "acceptance") -> path.local.LocalPath:
        return local.path(prefix, directory) / DIR

    @staticmethod
    def docker_status():
        logger.info("Docker containers")
        print(cmd.docker("ps", "-a", "-s"))

    @property
    def dc(self):
        return self.parent.test_state.dc

    @property
    def artifacts(self):
        return self.parent.test_state.artifacts

    @property
    def scion(self):
        return self.parent.test_state.scion

    @property
    def no_docker(self):
        return self.parent.test_state.no_docker


@TestBase.subcommand("name")
class TestName(CmdBase):
    def main(self):
        print(NAME)


@TestBase.subcommand("teardown")
class TestTeardown(CmdBase):
    """
    Teardown topology by stopping all running services..
    In a dockerized topology, the logs are collected.
    """
    @LogExec(logger, "teardown")
    def main(self):
        self.cmd_teardown()


def register_commands(c: Type[TestBase]):
    """
    Registers the default subcommands to the test class c.
    """
    class TestSetup(c):
        def main(self):
            self.setup()

    class TestRun(c):
        def main(self):
            self._run()

    class TestTeardown(c):
        def main(self):
            self.teardown()

    c.subcommand("setup", TestSetup)
    c.subcommand("run", TestRun)
    c.subcommand("teardown", TestTeardown)
