#!/usr/bin/env python3

# Copyright 2025 SCION Association
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

"""
Test that compares daemon vs standalone mode for end2end connectivity.

This test runs the end2end_integration test in two modes:
- Daemon mode: Uses remote SCION daemon connector (connecting via gRPC)
- Standalone mode: Uses embedded daemon with topology files (no sciond)

The daemon mode can be selected via --use-daemon flag:
- With --use-daemon: Uses remote daemon connector (via gRPC)
- Without --use-daemon (default): Uses standalone daemon connector
"""

from plumbum import cli

from acceptance.common import base


class Test(base.TestTopogen):
    """
    Tests end2end connectivity using either daemon or standalone mode.
    """

    use_daemon = cli.Flag(
        "--use-daemon",
        help="Use remote SCION daemon instead of standalone daemon",
    )

    def setup_start(self):
        super().setup_start()
        self.await_connectivity()

    def _run(self):
        ping_test = self.get_executable("end2end_integration")

        if self.use_daemon:
            print("=== Running with remote daemon (sciond) ===")
            ping_test["-d", "-sciond", "-outDir", self.artifacts].run_fg()
        else:
            print("=== Running with standalone daemon ===")
            ping_test["-d", "-outDir", self.artifacts].run_fg()


if __name__ == "__main__":
    base.main(Test)
