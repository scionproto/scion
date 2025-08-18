#!/usr/bin/env python3

# Copyright 2025 SCION Association

import time

from acceptance.common import base, scion
from tools.topology.scion_addr import ISD_AS

class Test(base.TestTopogen):
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

    def setup_prepare(self, no_transit_isd_number, no_transit_as_numbers):
        super().setup_prepare()

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
                {"beaconing.policies.propagation": "/etc/scion/policy.yaml"},
                [cs_toml_path])

            scion.write_file("""Filter:
                AllowTransitTraffic: False""", [policy_path])

    def setup_start(self):
        super().setup_start()
        # since some paths are not available, self.await_connectivity() doesn't work well
        time.sleep(15)

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

def main(test_class):
    base.main(test_class)
