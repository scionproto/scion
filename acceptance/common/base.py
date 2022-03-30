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
import re
import traceback
from typing import List

from plumbum import cli
from plumbum import local
from plumbum import cmd
from plumbum import LocalPath

from acceptance.common.docker import Compose
from acceptance.common import log

logger = logging.getLogger(__name__)


@cli.Predicate
def NameExecutable(arg):
    parts = arg.split(":")
    if len(parts) != 2:
        raise ValueError(arg)
    name, path = parts
    executable = local[cli.ExistingFile(path)]
    return (name, executable)


@cli.Predicate
def ContainerLoader(arg):
    parts = arg.split("#")
    if len(parts) != 2:
        raise ValueError(arg)
    tag, path = parts
    return (tag, cli.ExistingFile(path))


class TestBase:
    # XXX(matzf) should be executable?
    @cli.switch("executables", NameExecutable, list=True, help="Paths for executables, format name:path")
    def _set_executables(self, executables):
        self.executables = {name: executable for (name, executable) in executables}

    container_loaders = cli.SwitchAttr("container_loader", ContainerLoader, list=True,
                                       help="Container loader, format tag#path")
    setup_params = cli.SwitchAttr("setup-params", str, list=True,
                                  help="Additional setup parameters")

    artifacts = cli.SwitchAttr("artifacts-dir",
                               LocalPath,
                               envname="TEST_UNDECLARED_OUTPUTS_DIR",
                               default=LocalPath("/tmp/artifacts-scion"),
                               help="Directory for test artifacts. " +
                                    "Environment variable TEST_UNDECLARED_OUTPUTS_DIR")

    def setup(self):
        self.setup_prepare()
        self.setup_start()

    def _run(self):
        pass

    def teardown(self):
        pass

    def setup_prepare(self):
        """Unpacks loads local docker images and generates the topology.
        """
        self._setup_artifacts()
        self._setup_container_loaders()
        # Define where coredumps will be stored.
        print(
            cmd.docker("run", "--rm", "--privileged", "alpine", "sysctl", "-w",
                       "kernel.core_pattern=/share/coredump"))

    def setup_start(self):
        pass

    def _setup_artifacts(self):
        # Delete old artifacts, if any.
        cmd.rm("-rf", self.artifacts)
        cmd.mkdir(self.artifacts)
        print("artifacts dir: %s" % self.artifacts)

    def _setup_container_loaders(self):
        for tag, script in self.container_loaders:
            o = local[script]()
            idx = o.index("as ")
            if idx < 0:
                logger.error("extracting tag from loader script %s" % tag)
                continue
            bazel_tag = o[idx+len("as "):].strip()
            logger.info("docker tag %s %s" % (bazel_tag, tag))
            cmd.docker("tag", bazel_tag, tag)

    def get_executable(self, name: str):
        """Resolve the executable by name.

        If the executable is not in the executables mapping, the return value
        is './bin/<name>'
        """
        return self.executables.get(name, None) or local["./bin/" + name]


class TestTopogen(TestBase):
    topo = cli.SwitchAttr("topo", cli.ExistingFile, help="Config file for topogen, .topo")

    def setup_prepare(self):
        self.dc = None
        super().setup_prepare()
        self._setup_generate()

    def _setup_generate(self):
        """Generate the topology"""
        def copy_file(src, dst):
            cmd.mkdir("-p", os.path.dirname(dst))
            cmd.cp("-L", src, dst)

        copy_file(
            self.topo,
            self.artifacts / "topology.json",
        )
        copy_file(
            "tools/docker-ip",
            self.artifacts / "tools/docker-ip",
        )

        spki_path = os.path.dirname(self.get_executable("scion-pki").executable)
        path = spki_path + ":" + os.environ["PATH"]
        with local.cwd(self.artifacts):
            self.get_executable("topogen").with_env(PATH=path)(
                "-o=" + self.artifacts + "/gen",
                "-c=topology.json",
                "-d",
                *self.setup_params,
            )
        for support_dir in ["logs", "gen-cache", "gen-data", "traces"]:
            os.makedirs(self.artifacts / support_dir,
                        exist_ok=True)

    def setup_start(self):
        """Starts the docker containers in the topology.
        """
        self.dc = Compose(compose_file=self.artifacts / "gen/scion-dc.yml")
        print(self.dc("up", "-d"))
        ps = self.dc("ps")
        print(ps)
        if re.search(r"Exit\s+[1-9]\d*", ps):
            raise Exception("Failed services.\n" + ps)

    def teardown(self):
        if not self.dc:
            return
        out_dir = self.artifacts / "logs"
        self.dc.collect_logs(out_dir=out_dir)
        ps = self.dc("ps")
        print(self.dc("down", "-v"))
        if re.search(r"Exit\s+[1-9]\d*", ps):
            raise Exception("Failed services.\n" + ps)

    # XXX(matzf) move all these to Compose
    def start_container(self, container):
        """Starts the container with the specified name.

        Args:
            container: the name of the container.
        """
        print(self.dc("start", container))

    def restart_container(self, container):
        """Restarts the container with the specified name.

        Args:
            container: the name of the container.
        """
        print(self.dc("restart", container))

    def stop_container(self, container):
        """Stops the container with specified name.

        Args:
            container: the name of the container.
        """
        print(self.dc("stop", container))

    def list_containers(self, container_pattern: str) -> List[str]:
        """Lists all containers that match the given pattern.

        Args:
            container_pattern: A regex string to match the container. The regex
              format is standard Python regex format.

        Returns:
            A list of strings with the container names that match the
            container_pattern regex.
        """
        containers = self.dc("config", "--services")
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
        print(self.dc("kill", "-s", signal, container))

    def execute(self, container, *args, **kwargs):
        """Executes an arbitrary command in the specified container.

        There's one minute timeout on the command so that tests don't get stuck.

        Args:
            container: the name of the container to execute the command in.

        Returns:
            The output of the command.
        """
        user = kwargs.get("user", "{}:{}".format(os.getuid(), os.getgid()))
        return self.dc("exec", "-T", "--user", user, container,
                       "timeout", "1m", *args)


def main(test_class):
    log.init_log()

    class _TestMain(test_class, cli.Application):
        def main(self):
            if self.nested_command:
                return
            try:
                self.setup()
                self._run()
            except Exception:
                traceback.print_exc()
                return 1
            finally:
                self.teardown()

    class _TestSetup(test_class, cli.Application):
        def main(self):
            try:
                self.setup()
            except Exception:
                traceback.print_exc()
                return 1

    class _TestRun(test_class, cli.Application):
        def main(self):
            try:
                self._run()
            except Exception:
                traceback.print_exc()
                return 1

    class _TestTeardown(test_class, cli.Application):
        def main(self):
            try:
                self.teardown()
            except Exception:
                traceback.print_exc()
                return 1

    _TestMain.subcommand("setup", _TestSetup)
    _TestMain.subcommand("run", _TestRun)
    _TestMain.subcommand("teardown", _TestTeardown)
    _TestMain.run()
