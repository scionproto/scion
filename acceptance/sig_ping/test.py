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
from acceptance.common import base


class Test(base.TestTopogen):
    """
    Tests that IP pinging between Gateways works.
    """

    def _run(self):
        time.sleep(20)

        ping_test = self.get_executable("sig_ping_acceptance")

        print("Running ping test")
        ping_test["-d", "-outDir", self.artifacts].run_fg()
        print("Ping done")


if __name__ == "__main__":
    base.main(Test)
