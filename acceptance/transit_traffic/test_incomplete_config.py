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
    This test disallows transit traffic at only one of two core ASes in an ISD.
    It demonstrates that an incomplete configuration (only AS 120 blocks transit,
    while AS 110 does not) creates partial isolation: ISDs that both connect
    through the blocking AS lose connectivity to each other, but can still reach
    ISDs reachable through the non-blocking core AS.

    The graph without peering links looks as follows:
    411 123
    |   |
    410 121 122     111   211   612
      \    \ |      /     /     /
      310---120---110---210---610---620
      /      |                 |     | \
    311     510              611   621 622

    Transit traffic is blocked only at AS 120.
    """

    def setup_prepare(self):
        super().setup_prepare("1", ["120"])

    def _run(self):
        # ISD 3, 4 and 5 can reach ISD 2 because beacons pass through 120
        # to 110 (same-ISD hop, not blocked), and 110 forwards freely to 210.
        self._assert_bidirectional_path("310", "210")
        self._assert_bidirectional_path("410", "210")
        self._assert_bidirectional_path("311", "211")
        self._assert_bidirectional_path("411", "211")
        self._assert_bidirectional_path("510", "210")
        self._assert_bidirectional_path("510", "211")

        # ISD 3 and 4 cannot reach ISD 5: the only path goes through 120.
        self._assert_no_path_in_both_directions("310", "510")
        self._assert_no_path_in_both_directions("410", "510")
        self._assert_no_path_in_both_directions("311", "510")
        self._assert_no_path_in_both_directions("411", "510")

        # Direct neighbors of 120 are still reachable.
        self._assert_bidirectional_path("120", "310")
        self._assert_bidirectional_path("120", "510")
        self._assert_bidirectional_path("120", "110")

        # Intra-ISD traffic is unaffected.
        self._assert_bidirectional_path("410", "411")
        self._assert_bidirectional_path("310", "311")
        self._assert_bidirectional_path("110", "111")
        self._assert_bidirectional_path("122", "123")
        self._assert_bidirectional_path("610", "611")
        self._assert_bidirectional_path("620", "621")

        # ISD 3 and ISD 4 connectivity is not affected (doesn't need 120).
        self._assert_bidirectional_path("310", "410")
        self._assert_bidirectional_path("311", "411")

        # Beacons from ISDs 3, 4 and 5 all pass through 120->110
        # (same-ISD, not blocked) before reaching 210->610,
        # so core segments to ISD 6 exist from every ISD
        # and can be traversed in both directions.
        self._assert_bidirectional_path("610", "210")
        self._assert_bidirectional_path("610", "310")
        self._assert_bidirectional_path("610", "410")
        self._assert_bidirectional_path("610", "510")
        self._assert_bidirectional_path("611", "211")
        self._assert_bidirectional_path("611", "411")

if __name__ == "__main__":
    transit_traffic_base.main(Test)
