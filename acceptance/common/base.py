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


class Base(cli.Application):
    dc = DC('')  # Just init so mypy knows the type.
    tst_dir = local.path()  # Just init so mypy knows the type.
    no_docker = cli.Flag('disable-docker', envname='DISABLE_DOCKER',
                         help='Run in supervisor environment.')

    def __init__(self, executable):
        super().__init__(executable)
        self.scion = ScionSupervisor() if self.no_docker else ScionDocker()

    @cli.switch('--artifacts', str, envname='ACCEPTANCE_ARTIFACTS',
                mandatory=True)
    def artifacts_dir(self, a_dir: str):
        self.tst_dir = local.path('%s/%s/' % (a_dir, NAME))
        self.dc = DC(self.tst_dir)

    def cmd_dc(self, *args):
        for line in self.dc(*args).splitlines():
            print(line)

    def cmd_collect_logs(self):
        self.dc.collect_logs()

    def cmd_setup(self):
        mkdir('-p', self.tst_dir)

    def cmd_teardown(self):
        self.scion.stop()
        if not self.no_docker:
            self.dc.collect_logs(self.tst_dir / 'logs' / 'docker')

    @staticmethod
    def test_dir() -> LocalPath:
        return local.path('acceptance') / DIR

    @staticmethod
    def docker_status():
        logger.info('Docker containers')
        docker('ps', '-a', '-s')
        # TODO(lukedirtwalker): print status to stdout


@Base.subcommand('name')
class TestName(Base):
    def main(self):
        print(NAME)


@Base.subcommand('teardown')
class TestTeardown(Base):
    @LogExec(logger, 'teardown')
    def main(self):
        self.cmd_teardown()


@Base.subcommand('dc')
class TestDc(Base):
    def main(self, *args):
        self.cmd_dc(*args)


@Base.subcommand('collect_logs')
class TestCollectLogs(Base):
    def main(self):
        self.cmd_collect_logs()
