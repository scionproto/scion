#!/usr/bin/env python3

# Copyright 2023 ETH Zurich

from acceptance.common import base
from acceptance.common import scion


class Test(base.TestTopogen):
    """
    Constructs a simple test topology with one core, two leaf ASes.
    Each of them will run a different mix between BR that will replicate
    the legacy endhost-port-dispatch behaviour (i.e., they will send
    traffic to its own AS to the endhost default port) and
    application-port-dispatch routers (i.e., they will rewrite the underlay
    UDP/IP destination port with the UDP/SCION port).

    AS 1-ff00:0:1 is core.
    AS 1-ff00:0:2, 1-ff00:0:3 are leaves.

    We use the shortnames AS1, AS2, etc. for the ASes above.

    AS1 contains a BR with the port rewriting configuration to the default
    range. It also includes a shim dispatcher.
    AS2 contains a BR with a configuration that imitates the old
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
        scion.update_toml({"router.dispatched_port_start": 0,
                          "router.dispatched_port_end": 0},
                          [br_as_2_file])

    def setup_start(self):
        super().setup_start()
        self.await_connectivity()

    def _run(self):
        ping_test = self.get_executable("end2end_integration")
        ping_test["-d", "-outDir", self.artifacts].run_fg()


if __name__ == "__main__":
    base.main(Test)
