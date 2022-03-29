#!/usr/bin/env python3

# Copyright 2022 ETH Zurich
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
import time

from plumbum import local

from acceptance.common import base
from acceptance.common.base import TestBase, TestState, set_name
from acceptance.common.docker import Compose
from acceptance.common.scion import SCIONDocker


set_name(__file__)
logger = logging.getLogger(__name__)


class Test(TestBase):
    """
    On a SCION topology where end to end connectivity is available, after
    restarting the dispatcher and flushing SCIOND path databases, end to end
    connectivity should still be available.
    """

    def main(self):
        if not self.nested_command:
            print(self.test_state.executables)
            try:
                self.setup()
                time.sleep(10)
                self._run()
            finally:
                self.teardown()

    def _run(self):
        artifacts = self.test_state.artifacts
        end2end = local[self.test_state.executable("end2end_integration")]
        end2end_test = end2end[
            "-d",
            "-outDir", artifacts,
            "-src", "1-ff00:0:112",
            "-dst", "1-ff00:0:110",
            "-attempts", 5
        ]

        logger.info("==> Check connectivity")
        end2end_test.run_fg()

        dispatchers = self.list_containers("scion_disp_tester_1-ff00_0_11[02]$")
        assert len(dispatchers) == 2
        # Note: tester containers use network_mode: service: dispatcher...
        # When the dispatcher is stopped, the testers lose network access, and thus connection to
        # sciond, until they are restarted as well.
        testers = self.list_containers("tester_1-ff00_0_11[02]$")
        assert len(testers) == 2

        logger.info("==> Restarting dispatchers and testers: %s", dispatchers+testers)
        for c in dispatchers+testers:
            self.restart_container(c)

        daemon = "scion_sd1-ff00_0_112"
        logger.info("==> Flushing pathdb for daemon: %s", daemon)
        self.stop_container(daemon)
        pathdb = artifacts / "gen-cache/sd1-ff00_0_112.path.db"
        pathdb.delete()
        self.start_container(daemon)

        logger.info("==> Check connectivity")
        end2end_test.run_fg()


if __name__ == '__main__':
    base.register_commands(Test)
    Test.test_state = TestState(SCIONDocker(), Compose())
    Test.run()
