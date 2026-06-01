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

"""Acceptance test for multihomed endhost source-address selection.

Manual runs:
    bazel test --config=integration //acceptance/multihomed:test --test_output=streamed

The setup/run/teardown stages can also be exercised independently:
    bazel run //acceptance/multihomed:test_setup
    bazel run //acceptance/multihomed:test_run
    bazel run //acceptance/multihomed:test_teardown

Test flow:
1. Generate the tiny topology and keep the generated control-plane addressing unchanged.
2. Attach one extra compose-managed subnet to `br1-ff00_0_110-2` and to the AS110 tester
   namespace so the server gets a second address behind the second border router without
   rewriting the topology generator's internal BR addresses.
3. Start fresh unbound server instances in AS110 and probe them from AS111 and AS112,
   targeting the address that is reachable through each border router.
4. Start fresh bound server instances in AS110, one bound to the AS111-facing address
   and one bound to the AS112-facing address.
5. Require the client in all four cases to observe the reply coming back from the exact
   SCION source address it targeted.
"""

import time

import yaml
from plumbum import local

from acceptance.common import base


SERVER_PORT = 31000
SERVER_PRIMARY_IP = "172.20.0.22"
SERVER_SECONDARY_IP = "192.168.201.3"
SERVER_SECONDARY_BR_IP = "192.168.201.2"
SERVER_SECONDARY_SUBNET = "192.168.201.0/24"
SERVER_SECONDARY_NETWORK = "local_110_br2"

SERVER_IA = "1-ff00:0:110"
CLIENT_111_IA = "1-ff00:0:111"
CLIENT_112_IA = "1-ff00:0:112"

SERVER_CONTAINER = "tester_1-ff00_0_110"
CLIENT_111_CONTAINER = "tester_1-ff00_0_111"
CLIENT_112_CONTAINER = "tester_1-ff00_0_112"
SERVER_DISPATCHER = "disp_tester_1-ff00_0_110"
SERVER_BR2 = "br1-ff00_0_110-2"


class Test(base.TestTopogen):
    def setup_prepare(self):
        super().setup_prepare()

        # Add a second endhost-facing subnet behind br1-ff00_0_110-2 while leaving the
        # generated control-plane topology untouched. This is intentionally a compose-only
        # network change: the BR keeps its original generated internal address for SCION
        # control-plane traffic, while the server gains a second reachable host address for
        # the multihoming assertion. The raw packet-reversal server keeps the reply source
        # equal to the destination address that each client targeted.
        compose_path = self.artifacts / "gen/scion-dc.yml"
        with open(compose_path, "r", encoding="utf-8") as file:
            scion_dc = yaml.safe_load(file)

        scion_dc["networks"][SERVER_SECONDARY_NETWORK] = {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": SERVER_SECONDARY_SUBNET}]},
        }
        scion_dc["services"][SERVER_BR2]["networks"][SERVER_SECONDARY_NETWORK] = {
            "ipv4_address": SERVER_SECONDARY_BR_IP,
        }

        # Attach the secondary subnet to the container namespace that hosts the
        # test-server process. In some compose variants `tester_*` shares the
        # dispatcher namespace via `network_mode`, in others it has its own.
        server_service = scion_dc["services"][SERVER_CONTAINER]
        server_ns_service = (
            SERVER_DISPATCHER
            if "network_mode" in server_service and SERVER_DISPATCHER in scion_dc["services"]
            else SERVER_CONTAINER
        )
        scion_dc["services"][server_ns_service]["networks"][SERVER_SECONDARY_NETWORK] = {
            "ipv4_address": SERVER_SECONDARY_IP,
        }

        with open(compose_path, "w", encoding="utf-8") as file:
            yaml.safe_dump(scion_dc, file, sort_keys=False)

    def _run(self):
        self.await_connectivity()
        time.sleep(10)

        test_client = local["realpath"](self.get_executable("test-client").executable).strip()
        test_server = local["realpath"](self.get_executable("test-server").executable).strip()
        self.dc("cp", test_server, f"{SERVER_CONTAINER}:/bin/")
        self.dc("cp", test_client, f"{CLIENT_111_CONTAINER}:/bin/")
        self.dc("cp", test_client, f"{CLIENT_112_CONTAINER}:/bin/")

        print(
            "server IPs configured: primary=%s, secondary=%s"
            % (SERVER_PRIMARY_IP, SERVER_SECONDARY_IP)
        )
        self._run_scenario(
            client_container=CLIENT_111_CONTAINER,
            client_ia=CLIENT_111_IA,
            remote_ip=SERVER_PRIMARY_IP,
            bind_ip="0.0.0.0",
            label="AS111 -> AS110 via br1-ff00_0_110-1 with unbound server",
        )
        self._run_scenario(
            client_container=CLIENT_112_CONTAINER,
            client_ia=CLIENT_112_IA,
            remote_ip=SERVER_SECONDARY_IP,
            bind_ip="0.0.0.0",
            # The extra compose-managed subnet sits behind br1-ff00_0_110-2, so the
            # reply should be sourced from the second server address on that subnet.
            label="AS112 -> AS110 via br1-ff00_0_110-2 with unbound server",
        )
        self._run_scenario(
            client_container=CLIENT_111_CONTAINER,
            client_ia=CLIENT_111_IA,
            remote_ip=SERVER_PRIMARY_IP,
            bind_ip=SERVER_PRIMARY_IP,
            label="AS111 -> AS110 via br1-ff00_0_110-1 with server bound to primary IP",
        )
        self._run_scenario(
            client_container=CLIENT_112_CONTAINER,
            client_ia=CLIENT_112_IA,
            remote_ip=SERVER_SECONDARY_IP,
            bind_ip=SERVER_SECONDARY_IP,
            # The extra compose-managed subnet sits behind br1-ff00_0_110-2, so the
            # reply should be sourced from the second server address on that subnet.
            label="AS112 -> AS110 via br1-ff00_0_110-2 with server bound to secondary IP",
        )

    def _run_scenario(
        self,
        client_container: str,
        client_ia: str,
        remote_ip: str,
        bind_ip: str,
        label: str,
    ):
        remote = f"{SERVER_IA},{remote_ip}:{SERVER_PORT}"
        print(f"running {label}: {remote}")
        for attempt in range(2):
            # Make sure no stale server process from a previous scenario/attempt keeps
            # the port busy and causes a false negative timeout.
            self.dc.execute(
                SERVER_CONTAINER,
                "bash",
                "-c",
                "killall test-server >/dev/null 2>&1 || true",
            )
            self.dc.execute_detached(
                SERVER_CONTAINER,
                "bash",
                "-c",
                f'test-server -bind "{bind_ip}" -port {SERVER_PORT}',
            )
            time.sleep(3)
            try:
                result = self.dc.execute(
                    client_container,
                    "bash",
                    "-c",
                    (
                        f'test-client -local "{client_ia},0.0.0.0:0" '
                        f'-remote "{remote}" -expect "{remote}"'
                    ),
                )
                print(result)
                return
            except Exception:
                if attempt == 0:
                    print(f"scenario retry after first failure: {label}")
                    time.sleep(2)
                    continue
                raise


if __name__ == "__main__":
    base.main(Test)
