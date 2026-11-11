#!/usr/bin/env python3

# Copyright 2026 ETH Zurich
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
This test verifies that the end2end integration test works using the SCION endhost API.
"""

from acceptance.common import base


class Test(base.TestTopogen):

    def setup_start(self):
        super().setup_start()
        self.await_connectivity()

    def _run(self):
        ping_test = self.get_executable("end2end_integration")
        print("=== Running end2end integration with endhost API ===")
        ping_test["-d", "--endhost", "-outDir", self.artifacts].run_fg()


if __name__ == "__main__":
    base.main(Test)
