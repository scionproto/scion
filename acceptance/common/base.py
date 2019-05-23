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

from plumbum import cli
from plumbum import local
from plumbum.cmd import docker, mkdir
from plumbum.path.local import LocalPath

from acceptance.common.log import LogExec
from acceptance.common.scion import ScionDocker, ScionSupervisor
from acceptance.common.tools import DC

NAME = 'NOT_SET'  # must be set by users of the Base class.
DIR = 'NOT_SET'
logger = logging.getLogger(__name__)


def set_name(file: dir):
    global NAME
    global DIR
    DIR = local.path(file).dirname.name
    NAME = DIR[:-len('_acceptance')]


class TestState:
    """
    TestState is used to share state between the command
    and the sub-command.
    """
    dc = DC('')  # Just init so mypy knows the type.
    artifacts = local.path()  # Just init so mypy knows the type.
    scion = ScionDocker()
    no_docker = False
    tools_dc = local['./tools/dc']


class TestBase(cli.Application):
    """
    TestBase is used to implement the test entry point. Tests should
    sub-class it and only define the doc string.
    """

    @cli.switch('disable-docker', envname='DISABLE_DOCKER',
                help='Run in supervisor environment.')
    def disable_docker(self):
        TestState.no_docker = True
        TestState.scion = ScionSupervisor()

    @cli.switch('artifacts', str, envname='ACCEPTANCE_ARTIFACTS',
                mandatory=True)
    def artifacts_dir(self, a_dir: str):
        TestState.artifacts = local.path('%s/%s/' % (a_dir, NAME))


class CmdBase(cli.Application):
    """ CmdBase is used to implement the test sub-commands. """
    tools_dc = local['./tools/dc']

    def cmd_dc(self, *args):
        for line in self.dc(*args).splitlines():
            print(line)

    def cmd_collect_logs(self):
        self.dc.collect_logs()

    def cmd_setup(self):
        mkdir('-p', self.artifacts)

    def cmd_teardown(self):
        self.scion.stop()
        if not self.no_docker:
            self.dc.collect_logs(self.artifacts / 'logs' / 'docker')

    @staticmethod
    def test_dir() -> LocalPath:
        return local.path('acceptance') / DIR

    @staticmethod
    def docker_status():
        logger.info('Docker containers')
        docker('ps', '-a', '-s')
        # TODO(lukedirtwalker): print status to stdout

    @property
    def dc(self):
        return TestState.dc

    @property
    def artifacts(self):
        return TestState.artifacts

    @property
    def scion(self):
        return TestState.scion

    @property
    def no_docker(self):
        return TestState.no_docker


@TestBase.subcommand('name')
class TestName(CmdBase):
    def main(self):
        print(NAME)


@TestBase.subcommand('teardown')
class TestTeardown(CmdBase):
    """
    Teardown topology by stopping all running services..
    In a dockerized topology, the logs are collected.
    """

    @LogExec(logger, 'teardown')
    def main(self):
        self.cmd_teardown()


@TestBase.subcommand('dc')
class TestDc(CmdBase):
    """ Execute the docker-compose command. """

    def main(self, *args):
        self.cmd_dc(*args)


@TestBase.subcommand('collect_logs')
class TestCollectLogs(CmdBase):
    """ Collect the docker logs and write them to 'logs/docker'. """

    def main(self):
        self.cmd_collect_logs()
