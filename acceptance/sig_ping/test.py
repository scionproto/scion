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

import time

import plumbum

from acceptance.common import base
from acceptance.common import docker
from acceptance.common import scion


class Test(base.TestBase):
    """
    Tests that IP pinging between Gateways works.
    """
    gateway_acceptance = plumbum.cli.SwitchAttr("gateway_acceptance", str,
                                                default="./bin/sig_ping_acceptance",
                                                help="The gateway ping acceptance binary" +
                                                " (default: ./bin/sig_ping_acceptance)")

    def main(self):
        if not self.nested_command:
            try:
                self.setup()
                time.sleep(20)
                self._run()
            finally:
                self.teardown()

    def _run(self):
        ping_test = plumbum.local[self.gateway_acceptance]

        print("Running ping test")
        print(ping_test("-d", "-outDir", self.test_state.artifacts))
        print("Ping done")


if __name__ == "__main__":
    base.register_commands(Test)
    Test.test_state = base.TestState(scion.SCIONDocker(), docker.Compose())
    Test.run()
