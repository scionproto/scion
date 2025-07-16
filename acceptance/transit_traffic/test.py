#!/usr/bin/env python3

# Copyright 2025 SCION Association

import http.server
import time
import threading

from acceptance.common import base, scion
from tools.topology.scion_addr import ISD_AS

class Test(base.TestTopogen):
    """
    TODO: Fill in the test description here.

    The graph without peering links looks as follows:
    411 123
    |   |
    410 121 122     111   211
      \    \ |      /     /
      310---120---110---210
      /      |
    311     510
    """
    _ases = {
        "110": "1-ff00:0:110",
        "111": "1-ff00:0:111",
        "120": "1-ff00:0:120",
        "121": "1-ff00:0:121",
        "122": "1-ff00:0:122",
        "123": "1-ff00:0:123",
        "210": "2-ff00:0:210",
        "211": "2-ff00:0:210",
        "310": "3-ff00:0:310",
        "311": "3-ff00:0:311",
        "410": "4-ff00:0:410",
        "411": "4-ff00:0:411",
        "510": "5-ff00:0:510",
    }

    def setup_prepare(self):
        super().setup_prepare()

        no_transit_isd_number = "3"
#         no_transit_as_numbers = ["310", "311"]
        no_transit_as_numbers = ["310"]

        for as_number in no_transit_as_numbers:
            as_number_string = "ff00_0_%s" % as_number
            as_relative_dir_path = "AS%s" % as_number_string
            as_absolute_dir_path = self.artifacts / "gen" / as_relative_dir_path

            cs_toml_path = (
                as_absolute_dir_path
                / ("cs%s-%s-1.toml" % (no_transit_isd_number, as_number_string))
            )
            policy_path = as_absolute_dir_path / "policy.yaml"
            scion.update_toml(
                {"beaconing.policies.propagation": "gen/%s/policy.yaml" % as_relative_dir_path},
                [cs_toml_path])

            scion.write_file("""Filter:
                AllowTransitTraffic: False""", [policy_path])

    def setup_start(self):
        super().setup_start()
#         self.await_connectivity()

    def _run(self):
        # TODO: re-check await_connectivity
        time.sleep(15)

        # TODO: re-check
        # Traffic originating or ending in ISD 3 is allowed.
#         self._assert_bidirectional_path("310", "410")
#         self._assert_bidirectional_path("311", "410")
#         self._assert_bidirectional_path("310", "411")
#         self._assert_bidirectional_path("311", "411")
#         self._assert_bidirectional_path("310", "210")
#         self._assert_bidirectional_path("311", "123")
#         self._assert_bidirectional_path("310", "510")
#         self._assert_bidirectional_path("311", "111")

        # Transit traffic via ISD 3 is not allowed.
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

    def _showpaths(self, source_as: str, destination_as: str):
        print(self.execute_tester(ISD_AS(self._ases[source_as]),
                                  "scion", "sp", self._ases[destination_as], "--timeout", "2s"))

    def _assert_path(self, source_as: str, destination_as: str):
        try:
             self._showpaths(source_as, destination_as)
        except Exception as e:
            raise AssertionError(f"No path found: {source_as} -> {destination_as}")
        self._showpaths(source_as, destination_as)

    def _assert_bidirectional_path(self, source_as: str, destination_as: str):
        self._assert_path(source_as, destination_as)
        self._assert_path(destination_as, source_as)

    def _assert_no_path(self, source_as: str, destination_as: str):
         try:
             self._showpaths(source_as, destination_as)
         except Exception as e:
             print(e)
         else:
             raise AssertionError(f"Unexpected path: {source_as} -> {destination_as}")

    def _assert_no_path_in_both_directions(self, source_as: str, destination_as: str):
        self._assert_no_path(source_as, destination_as)
        self._assert_no_path(destination_as, source_as)

if __name__ == "__main__":
    base.main(Test)
