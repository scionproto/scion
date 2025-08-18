#!/usr/bin/env python3

# Copyright 2025 SCION Association

from acceptance.transit_traffic import transit_traffic_base

class Test(transit_traffic_base.Test):
    """
    This test disallows traffic in only one AS in one ISD and checks the resulting paths.
    This config doesn't make much sense in a real-life scenario,
    but shows what happens in case of misconfiguration of one AS in the ISD.

    The graph without peering links looks as follows:
    411 123
    |   |
    410 121 122     111   211
      \    \ |      /     /
      310---120---110---210
      /      |
    311     510

    Transit traffic via is not allowed only via AS 310: 311 doesn't have this configured.
    """

    def setup_prepare(self):
        super().setup_prepare("3", ["310"])

    def _run(self):
        # Traffic originating or ending in AS 310 is allowed.
        self._assert_bidirectional_path("310", "410")
        self._assert_bidirectional_path("310", "110")
        self._assert_bidirectional_path("310", "510")

        self._assert_bidirectional_path("311", "122")

        # Transit traffic via AS 310 is not allowed.
        self._assert_no_path_in_both_directions("410", "210")
        self._assert_no_path_in_both_directions("411", "211")
        self._assert_no_path_in_both_directions("411", "510")
        self._assert_no_path_in_both_directions("410", "123")
        self._assert_no_path_in_both_directions("410", "111")

        # Traffic outside of ISD 3 is not affected.
        self._assert_bidirectional_path("123", "510")
        self._assert_bidirectional_path("123", "211")
        self._assert_bidirectional_path("122", "111")
        self._assert_bidirectional_path("120", "210")
        self._assert_bidirectional_path("510", "211")
        self._assert_bidirectional_path("111", "211")
        self._assert_bidirectional_path("410", "411")

if __name__ == "__main__":
    transit_traffic_base.main(Test)
