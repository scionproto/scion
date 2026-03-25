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
    This test disallows transit traffic at all core ASes in ISD 1,
    the central hub ISD. It differs from ISD 3 test since there are
    no peering links between ISDs 1,2,4,5 and ISDs 2,6.

    The graph picture can be found here: topology/testdata/big.topo.png

    With transit blocked at both 110 and 120, ISD 1 becomes a wall:
    each neighboring ISD can reach ISD 1 via 2-ISD origination beacons,
    but no beacon transits through ISD 1 to connect two other ISDs.
    Only ISDs with direct core links bypass ISD 1:
    ISD 3 <-> ISD 4 (310-410) and ISD 2 <-> ISD 6 (210-610).
    """

    def setup_prepare(self):
        super().setup_prepare("1", ["110", "120"])

    def _run(self):
        # Traffic originating or ending in ISD 1 is allowed.
        self._assert_bidirectional_path("210", "110")
        self._assert_bidirectional_path("310", "120")
        self._assert_bidirectional_path("410", "110")
        self._assert_bidirectional_path("510", "120")
        self._assert_bidirectional_path("610", "110")
        self._assert_bidirectional_path("211", "111")
        self._assert_bidirectional_path("311", "121")
        self._assert_bidirectional_path("611", "111")
        self._assert_bidirectional_path("110", "111")
        self._assert_bidirectional_path("120", "122")

        # Traffic outside of ISD 1 is not affected.
        self._assert_bidirectional_path("310", "410")
        self._assert_bidirectional_path("311", "411")
        self._assert_bidirectional_path("210", "610")
        self._assert_bidirectional_path("211", "611")
        self._assert_bidirectional_path("310", "311")
        self._assert_bidirectional_path("410", "411")
        self._assert_bidirectional_path("610", "611")
        self._assert_bidirectional_path("620", "621")

        # Transit traffic via ISD 1 is not allowed.
        self._assert_no_path_in_both_directions("210", "310")
        self._assert_no_path_in_both_directions("210", "510")
        self._assert_no_path_in_both_directions("310", "510")
        self._assert_no_path_in_both_directions("310", "610")
        self._assert_no_path_in_both_directions("410", "510")
        self._assert_no_path_in_both_directions("410", "610")
        self._assert_no_path_in_both_directions("510", "610")
        self._assert_no_path_in_both_directions("211", "311")
        self._assert_no_path_in_both_directions("411", "611")

if __name__ == "__main__":
    transit_traffic_base.main(Test)
