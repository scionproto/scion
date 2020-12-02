#!/usr/bin/env python3

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

import logging
import time

import plumbum
from plumbum import cmd

from acceptance.common import base
from acceptance.common import log
from acceptance.common import tools
from acceptance.common import scion


base.set_name(__file__)
logger = logging.getLogger(__name__)


class Test(base.TestBase):
    """
    Tests that IP pinging between SIGs works.
    """
    sig_acceptance = plumbum.cli.SwitchAttr("sig_acceptance", str,
                                            default="./bin/sig_ping_acceptance",
                                            help="The sig_ping_acceptance binary" +
                                            " (default: ./bin/sig_ping_acceptance)")

    def main(self):
        print("artifacts dir: %s" % self.test_state.artifacts)
        self._unpack_topo()
        if not self.nested_command:
            try:
                self._setup()
                self._run()
            finally:
                self._teardown()

    def _unpack_topo(self):
        # Unpack the topogen output, adapt SCIONROOT.
        cmd.tar("-xf", "./acceptance/sig_ping/gen.tar",
                "-C", self.test_state.artifacts)
        cmd.sed("-i", "s#$SCIONROOT#%s#g" % self.test_state.artifacts,
                self.test_state.artifacts / "gen/scion-dc.yml")

    def _docker_compose(self, *args) -> str:
        return cmd.docker_compose("-f", self.test_state.artifacts / "gen" / "scion-dc.yml",
                                  "-p", "scion", *args)

    def _setup(self):
        # First load the images
        print(cmd.docker("image", "load", "-i",
              "./acceptance/sig_ping/testcontainers.tar"))

        # Start the topology, wait for everything to be ready.
        print(self._docker_compose("up", "-d"))
        # Give some time, so revocation can be gone.
        print("wait for topology to be ready")
        time.sleep(30)
        print(self._docker_compose("ps"))
        print("setup done")

    def _run(self):
        ping_test = plumbum.local[self.sig_acceptance]

        print("Running ping test")
        print(ping_test("-d", "-outDir", self.test_state.artifacts))
        print("Ping done")

    def _teardown(self):
        logs = self._docker_compose("logs")
        with open(self.test_state.artifacts / "logs" / "docker-compose.log", "w") as f:
            f.write(logs)
        print(self._docker_compose("down", "-v"))


@Test.subcommand("setup")
class TestSetup(Test):

    def main(self):
        self._setup()


@Test.subcommand("run")
class TestRun(Test):

    def main(self):
        self._run()


@Test.subcommand("teardown")
class TestTeardown(Test):

    def main(self):
        self._teardown()


if __name__ == "__main__":
    log.init_log()
    Test.test_state = base.TestState(scion.SCIONDocker(), tools.DC())
    Test.run()
