#!/usr/bin/env python3

# Copyright 2026 SCION Association
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

from acceptance.transit_traffic import transit_traffic_base

class Test(transit_traffic_base.Test):
    """
    This test disallows transit traffic in all ASes of ISD 3 and checks the
    resulting paths. It differs from ISD 1 test since there are
    peering links between ISD 4 and ISD 1.

    The graph without peering links looks as follows:
    411 123
    |   |
    410 121 122     111   211   612
      \    \ |      /     /     /
      310---120---110---210---610---620
      /      |                 |     | \
    311     510              611   621 622

    Transit traffic is blocked at all ASes in ISD 3 (310 and 311).
    """

    def setup_prepare(self):
        super().setup_prepare("3", ["310", "311"])

    def _run(self):
        # Traffic originating or ending in ISD 3 is allowed.
        self._assert_bidirectional_path("310", "410")
        self._assert_bidirectional_path("311", "410")
        self._assert_bidirectional_path("310", "411")
        self._assert_bidirectional_path("311", "411")
        self._assert_bidirectional_path("310", "210")
        self._assert_bidirectional_path("311", "123")
        self._assert_bidirectional_path("310", "510")
        self._assert_bidirectional_path("311", "111")
        self._assert_bidirectional_path("310", "610")
        self._assert_bidirectional_path("311", "611")

        # Transit traffic via ISD 3 is not allowed.
        # TODO should work via peering link 120-410
        self._assert_no_path_in_both_directions("410", "210")
        # TODO should work via peering link 123-411
        self._assert_no_path_in_both_directions("411", "211")
        # TODO should work via peering link 123-411
        self._assert_no_path_in_both_directions("411", "510")
        # TODO should work via peering link 123-410
        self._assert_no_path_in_both_directions("410", "123")
        # TODO should work via peering link 123-411
        self._assert_no_path_in_both_directions("411", "123")
        # TODO should work via peering link 120-410
        self._assert_no_path_in_both_directions("410", "111")
        # ISD 4 cannot reach ISD 6 (only core path goes through 310).
        # TODO should work via peering link 120-410
        self._assert_no_path_in_both_directions("410", "610")
        # TODO should work via peering link 123-411
        self._assert_no_path_in_both_directions("411", "611")

        # Traffic outside of ISD 3 is not affected.
        self._assert_bidirectional_path("123", "510")
        self._assert_bidirectional_path("123", "211")
        self._assert_bidirectional_path("122", "111")
        self._assert_bidirectional_path("120", "210")
        self._assert_bidirectional_path("510", "211")
        self._assert_bidirectional_path("111", "211")
        self._assert_bidirectional_path("410", "411")
        self._assert_bidirectional_path("610", "210")
        self._assert_bidirectional_path("610", "110")
        self._assert_bidirectional_path("610", "510")
        self._assert_bidirectional_path("611", "211")
        self._assert_bidirectional_path("610", "611")
        self._assert_bidirectional_path("620", "621")

if __name__ == "__main__":
    transit_traffic_base.main(Test)
