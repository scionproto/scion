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

"""Acceptance test for probing a container attached to two tiny-topology networks.

Manual runs:
    bazel test --config=integration //acceptance/multihomed:test --test_output=streamed
"""

import time

import yaml

from acceptance.common import base


PROBE_CONTAINER = "probe_1-ff00_0_111_112"
PROBE_IMAGE = "alpine:latest"

AS111_INTERNAL_NETWORK = "scn_002"
AS111_PROBE_IP = "172.20.0.30"
AS111_BR_INTERNAL_IP = "172.20.0.26"

AS112_INTERNAL_NETWORK = "scn_004"
AS112_PROBE_IP = "fd00:f00d:cafe::7f00:16"
AS112_BR_INTERNAL_IP = "fd00:f00d:cafe::7f00:12"


class Test(base.TestTopogen):
    def setup_prepare(self):
        super().setup_prepare()

        with open(self.artifacts / "gen/scion-dc.yml", "r", encoding="utf-8") as file:
            scion_dc = yaml.safe_load(file)

        # Add a helper container that can live on both internal networks at once.
        scion_dc["services"][PROBE_CONTAINER] = {
            "image": PROBE_IMAGE,
            "command": 'sh -c "tail -f /dev/null"',
            "networks": {
                AS111_INTERNAL_NETWORK: {"ipv4_address": AS111_PROBE_IP},
                AS112_INTERNAL_NETWORK: {"ipv6_address": AS112_PROBE_IP},
            },
        }

        with open(self.artifacts / "gen/scion-dc.yml", "w", encoding="utf-8") as file:
            yaml.safe_dump(scion_dc, file, sort_keys=False)

    def _run(self):
        print("[multihomed] waiting for control/data-plane connectivity")
        self.await_connectivity()
        print("[multihomed] connectivity reported ready; waiting extra 5s for stabilization")
        time.sleep(5)

        print(f"[multihomed] probe container={PROBE_CONTAINER}")
        print(
            "[multihomed] expected attachments: "
            f"{AS111_INTERNAL_NETWORK}={AS111_PROBE_IP}, "
            f"{AS112_INTERNAL_NETWORK}={AS112_PROBE_IP}"
        )

        print("[multihomed] probe interfaces")
        print(
            self.dc.execute(
                PROBE_CONTAINER,
                "sh",
                "-c",
                "ip -o addr show || ifconfig -a || cat /proc/net/dev",
            )
        )

        print("[multihomed] probe routes")
        print(
            self.dc.execute(
                PROBE_CONTAINER,
                "sh",
                "-c",
                "ip route show || route -n || cat /proc/net/route",
            )
        )

        print(f"[multihomed] pinging AS111 BR internal address {AS111_BR_INTERNAL_IP}")
        print(
            self.dc.execute(
                PROBE_CONTAINER,
                "sh",
                "-c",
                f"ping -c3 {AS111_BR_INTERNAL_IP}",
            )
        )

        print(f"[multihomed] pinging AS112 BR internal address {AS112_BR_INTERNAL_IP}")
        print(
            self.dc.execute(
                PROBE_CONTAINER,
                "sh",
                "-c",
                f"ping -6 -c3 {AS112_BR_INTERNAL_IP} || ping6 -c3 {AS112_BR_INTERNAL_IP}",
            )
        )


if __name__ == "__main__":
    base.main(Test)
