#!/usr/bin/env python3

# Copyright 2023 ETH Zurich

import time

from acceptance.common import base
from acceptance.common import scion
# from plumbum import local


class Test(base.TestTopogen):
    """
    Constructs a simple test topology with one core, four leaf ASes.
    Each of them will run a different mix between BR that will replicate
    the old behaviour (i.e., they will send traffic to its own AS to the
    endhost default port) and routers with the new behaviour (i.e., they
    will rewrite the underlay UDP/IP destination port with the UDP/SCION
    port).

    AS 1-ff00:0:1 is core.
    AS 1-ff00:0:2, 1-ff00:0:3

    We use the shortnames AS1, AS2, etc. for the ASes above.

    AS1 contains a BR with the port rewriting configuration to the default
    range. It also includes a shim dispatcher.
    AS2 contains a BR with a configuration that reassembles the old
    behaviour, i.e., sending all traffic to default endhost port 30041.
    It also includes a shim dispatcher.
    AS3 contains a BR with the port rewriting configuration to the default
    range. It does not include the shim dispatcher.
    """

    def setup_prepare(self):
        super().setup_prepare()

        br_as_2_id = "br1-ff00_0_2-1"

        br_as_2_file = self.artifacts / "gen" / "ASff00_0_2" \
            / ("%s.toml" % br_as_2_id)
        scion.update_toml({"router.endhost_start_port": 0}, [br_as_2_file])
        scion.update_toml({"router.endhost_end_port": 0}, [br_as_2_file])

    def setup_start(self):
        super().setup_start()
        time.sleep(10)  # Give applications time to download configurations

    def _run(self):
        ping_test = self.get_executable("end2end_integration")
        ping_test["-d", "-outDir", self.artifacts].run_fg()


if __name__ == "__main__":
    base.main(Test)
