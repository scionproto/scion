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
from abc import abstractmethod, ABC

from plumbum import cli
from plumbum import local
from plumbum import cmd
from plumbum import LocalPath

from acceptance.common import docker, log
from tools.topology.scion_addr import ISD_AS

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


class TestBase(ABC):
    """
    Base class for tests. Tests are executed as:
        - init
        - setup, consisting of the sub steps
            - setup_prepare
            - setup_start
        - _run
        - teardown

    A test can override any of these methods.
    The `_run` method must be defined by each test.

    The commandline subcommands for `setup`, `run` and `teardown` allow to run the steps separately.
    The `init` function is always called.

    Tests should write all their artifacts to the directory `self.artifacts`, which is created
    during setup.
    """

    @cli.switch("executable", NameExecutable, list=True,
                help="Paths for executables, format name:path")
    def _set_executables(self, executables):
        self.executables = {name: executable for (name, executable) in executables}

    container_loaders = cli.SwitchAttr("container-loader", ContainerLoader, list=True,
                                       help="Container loader, format tag#path")

    artifacts = cli.SwitchAttr("artifacts-dir",
                               LocalPath,
                               envname="TEST_UNDECLARED_OUTPUTS_DIR",
                               default=LocalPath("/tmp/artifacts-scion"),
                               help="Directory for test artifacts. " +
                                    "Environment variable TEST_UNDECLARED_OUTPUTS_DIR")

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._setup_prepare_failed = False

    def init(self):
        """ init is called first. The Test object can be initialized here.
        The cli parameters have already been parsed when this is called (contrasting to __init__).
        """
        pass

    def setup(self):
        try:
            self._setup_prepare_failed = False
            self.setup_prepare()
        except:  # noqa E722, we really want to handle any exception
            self._setup_prepare_failed = True
            raise
        self.setup_start()

    @abstractmethod
    def _run(self):
        """Run the actual test. Must be implemented by concrete test.
        Note: underscored name because this clashes with plumbum.cli.Application
        """
        pass

    def teardown(self):
        pass

    def setup_prepare(self):
        """Unpacks loads local docker images and generates the topology.
        """
        docker.assert_no_networks()
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
    setup_params = cli.SwitchAttr("setup-params", str, list=True,
                                  help="Additional parameters for topogen")

    def init(self):
        super().init()
        self.dc = docker.Compose(compose_file=self.artifacts / "gen/scion-dc.yml")

    def setup_prepare(self):
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
        print(self.dc("up", "-d"))
        ps = self.dc("ps")
        print(ps)
        if re.search(r"Exit\s+[1-9]\d*", ps):
            raise Exception("Failed services.\n" + ps)

    def teardown(self):
        # Avoid running docker-compose teardown if setup_prepare failed
        if self._setup_prepare_failed:
            return
        out_dir = self.artifacts / "logs"
        self.dc.collect_logs(out_dir=out_dir)
        ps = self.dc("ps")
        print(self.dc("down", "-v"))
        if re.search(r"Exit\s+[1-9]\d*", ps):
            raise Exception("Failed services.\n" + ps)

    def execute_tester(self, isd_as: ISD_AS, cmd: str, *args: str) -> str:
        """Executes a command in the designated "tester" container for the specified ISD-AS.

        Returns:
            The output of the command.
        """
        return self.dc.execute("tester_%s" % isd_as.file_fmt(), cmd, *args)


def main(test_class):
    log.init_log()

    class _TestMain(test_class, cli.Application):
        __doc__ = test_class.__doc__
        CALL_MAIN_IF_NESTED_COMMAND = False

        def main(self):
            self.init()
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
            self.init()
            try:
                self.setup()
            except Exception:
                traceback.print_exc()
                return 1

    class _TestRun(test_class, cli.Application):
        def main(self):
            self.init()
            try:
                self._run()
            except Exception:
                traceback.print_exc()
                return 1

    class _TestTeardown(test_class, cli.Application):
        def main(self):
            self.init()
            try:
                self.teardown()
            except Exception:
                traceback.print_exc()
                return 1

    _TestMain.subcommand("setup", _TestSetup)
    _TestMain.subcommand("run", _TestRun)
    _TestMain.subcommand("teardown", _TestTeardown)
    _TestMain.run()
