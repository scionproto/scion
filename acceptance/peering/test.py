#!/usr/bin/env python3

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

    def setup_start(self):
        super().setup_start()
        self.await_connectivity()

    def _run(self):
        self._showpaths("111", "210")
        raise AssertionError(f"Only one path is found with 3 hops, without peering links")

    def _showpaths(self, source_as: str, destination_as: str):
        print(self.execute_tester(ISD_AS(self._ases[source_as]),
                                  "scion", "sp", self._ases[destination_as], "--timeout", "2s"))

if __name__ == "__main__":
    base.main(Test)
