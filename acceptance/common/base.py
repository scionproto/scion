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

from plumbum import cli
from plumbum import local
from plumbum import cmd
from plumbum import path

from acceptance.common.log import LogExec
from acceptance.common.scion import SCION, SCIONSupervisor
from acceptance.common.tools import DC

NAME = 'NOT_SET'  # must be set by users of the Base class.
DIR = 'NOT_SET'
logger = logging.getLogger(__name__)


def set_name(file: str):
    global NAME
    global DIR
    DIR = local.path(file).dirname.name
    NAME = DIR[:-len('_acceptance')]


class TestState:
    """
    TestState is used to share state between the command
    and the sub-command.
    """

    def __init__(self, scion: SCION, dc: DC):
        """
        Create new environment state for an execution of the acceptance
        testing framework. Plumbum subcommands can access this state
        via the parent to retrieve information about the test environment.
        """

        self.scion = scion
        self.dc = dc
        self.topology_tar = ""
        self.containers_tar = ""
        if 'TEST_UNDECLARED_OUTPUTS_DIR' in os.environ:
            self.artifacts = local.path(os.environ['TEST_UNDECLARED_OUTPUTS_DIR'])
        else:
            self.artifacts = local.path(cmd.mktemp('-d').strip())
        self.dc.compose_file = self.artifacts / 'gen/scion-dc.yml'
        self.no_docker = False
        self.tools_dc = local['./tools/dc']


class TestBase(cli.Application):
    """
    TestBase is used to implement the test entry point. Tests should
    sub-class it and only define the doc string.
    """
    test_state = None  # type: TestState

    @cli.switch('disable-docker', envname='DISABLE_DOCKER',
                help='Run in supervisor environment.')
    def disable_docker(self):
        self.test_state.no_docker = True
        self.test_state.scion = SCIONSupervisor()

    @cli.switch('artifacts', str, envname='ACCEPTANCE_ARTIFACTS',
                help='Artifacts directory')
    def artifacts_dir(self, a_dir: str):
        self.test_state.artifacts = local.path('%s/%s/' % (a_dir, NAME))

    @cli.switch('topology_tar', str, help="The tarball with the topology files")
    def topology_tar(self, tar: str):
        self.test_state.topology_tar = tar

    @cli.switch('containers_tar', str, help="The tarball with the containers")
    def containers_tar(self, tar: str):
        self.test_state.containers_tar = tar


class CmdBase(cli.Application):
    """ CmdBase is used to implement the test sub-commands. """
    tools_dc = local['./tools/dc']

    def cmd_dc(self, *args):
        for line in self.dc(*args).splitlines():
            print(line)

    def cmd_setup(self):
        cmd.mkdir('-p', self.artifacts)

    def cmd_teardown(self):
        if not self.no_docker:
            self.dc.collect_logs(self.artifacts / 'logs' / 'docker')
            self.tools_dc('down')
        self.scion.stop()

    def _collect_logs(self, name: str):
        if path.local.LocalPath('gen/%s-dc.yml' % name).exists():
            self.tools_dc('collect_logs', name, self.artifacts / 'logs' / 'docker')

    def _teardown(self, name: str):
        if path.local.LocalPath('gen/%s-dc.yml' % name).exists():
            self.tools_dc(name, 'down')

    @staticmethod
    def test_dir(prefix: str = '', directory: str = 'acceptance') -> path.local.LocalPath:
        return local.path(prefix, directory) / DIR

    @staticmethod
    def docker_status():
        logger.info('Docker containers')
        print(cmd.docker('ps', '-a', '-s'))

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
