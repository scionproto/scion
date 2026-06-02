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

"""Acceptance test for a multihomed server container in the tiny topology.

Manual runs:
    bazel test --config=integration //acceptance/multihomed:test --test_output=streamed
"""

import time

import yaml
from plumbum import local

from acceptance.common import base
from acceptance.common.docker import _CalledProcessErrorWithOutput


SERVER_CONTAINER = "probe_1-ff00_0_111_multi"
SERVER_IMAGE = "scion/tester:latest"
SERVER_PORT = 31000

AS111_INTERNAL_NETWORK = "scn_002"
AS111_INTERNAL_SERVER_IP = "172.20.0.30"
AS111_INTERNAL_BR_IP = "172.20.0.26"

AS111_EXTRA_NETWORK = "scn_111_multi"
AS111_EXTRA_SUBNET = "172.20.1.0/29"
AS111_EXTRA_SERVER_IP = "172.20.1.3"
AS111_EXTRA_BR_IP = "172.20.1.2"

AS112_CLIENT_CONTAINER = "tester_1-ff00_0_112"
AS112_CLIENT_IA = "1-ff00:0:112"
AS112_CLIENT_LOCAL = f'{AS112_CLIENT_IA},[::]:0'
AS111_SERVER_IA = "1-ff00:0:111"


class Test(base.TestTopogen):
    def setup_prepare(self):
        super().setup_prepare()

        with open(self.artifacts / "gen/scion-dc.yml", "r", encoding="utf-8") as file:
            scion_dc = yaml.safe_load(file)

        scion_dc["networks"][AS111_EXTRA_NETWORK] = {
            "driver": "bridge",
            "driver_opts": {
                "com.docker.network.bridge.name": AS111_EXTRA_NETWORK,
            },
            "ipam": {
                "config": [{"subnet": AS111_EXTRA_SUBNET}],
            },
        }

        scion_dc["services"]["br1-ff00_0_111-1"]["networks"][AS111_EXTRA_NETWORK] = {
            "ipv4_address": AS111_EXTRA_BR_IP,
        }

        scion_dc["services"][SERVER_CONTAINER] = {
            "image": SERVER_IMAGE,
            "command": 'bash -c "tail -f /dev/null"',
            "cap_add": ["NET_ADMIN", "NET_RAW"],
            "privileged": True,
            "networks": {
                AS111_INTERNAL_NETWORK: {"ipv4_address": AS111_INTERNAL_SERVER_IP},
                AS111_EXTRA_NETWORK: {"ipv4_address": AS111_EXTRA_SERVER_IP},
            },
        }

        with open(self.artifacts / "gen/scion-dc.yml", "w", encoding="utf-8") as file:
            yaml.safe_dump(scion_dc, file, sort_keys=False)

    def _run(self):
        print("[multihomed] waiting for control/data-plane connectivity")
        self.await_connectivity()
        print("[multihomed] connectivity reported ready; waiting extra 5s for stabilization")
        time.sleep(5)

        test_client = local["realpath"](self.get_executable("test-client").executable).strip()
        test_server = local["realpath"](self.get_executable("test-server").executable).strip()
        print(f"[multihomed] test-client binary={test_client}")
        print(f"[multihomed] test-server binary={test_server}")

        print("[multihomed] copying test binaries into containers")
        self.dc("cp", test_server, f"{SERVER_CONTAINER}:/bin/test-server")
        self.dc("cp", test_client, f"{AS112_CLIENT_CONTAINER}:/bin/test-client")

        self._print_server_interfaces()
        self._print_server_routes()

        iface_by_ip = self._server_interfaces_by_ip()
        primary_iface = iface_by_ip[AS111_INTERNAL_SERVER_IP]
        secondary_iface = iface_by_ip[AS111_EXTRA_SERVER_IP]
        print(
            "[multihomed] server address/interface mapping: "
            f"{AS111_INTERNAL_SERVER_IP}={primary_iface}, "
            f"{AS111_EXTRA_SERVER_IP}={secondary_iface}"
        )

        self._ping_br_via_interface(primary_iface, AS111_INTERNAL_BR_IP)
        self._ping_br_via_interface(secondary_iface, AS111_EXTRA_BR_IP)

        print("[multihomed] starting first test-server instance bound to 0.0.0.0")
        self._start_server()
        self._print_server_output()
        print(
            "[multihomed] first client run from AS112 to server primary address "
            f"{AS111_INTERNAL_SERVER_IP}:{SERVER_PORT}"
        )
        first_result = self._run_client(AS111_INTERNAL_SERVER_IP)
        print("[multihomed] first client output begin")
        print(first_result)
        print("[multihomed] first client output end")
        self._print_server_output()

        print(f"[multihomed] bringing down interface {primary_iface} in server container")
        print(
            self.dc.execute(
                SERVER_CONTAINER,
                "bash",
                "-c",
                " && ".join([
                    f"ip link set dev {primary_iface} down",
                    f"ip -o addr show dev {primary_iface} || true",
                ]),
                user="0:0",
            )
        )
        self._print_server_interfaces()
        self._print_server_routes()
        self._print_server_process_list()
        self._print_server_sockets()

        print(
            "[multihomed] second client run from AS112 to server primary address; "
            "this is expected to fail"
        )
        self._assert_client_failure(AS111_INTERNAL_SERVER_IP)
        self._print_server_process_list()
        self._print_server_output()

        print(
            "[multihomed] third client run from AS112 to server secondary address "
            f"{AS111_EXTRA_SERVER_IP}:{SERVER_PORT}; this should succeed"
        )
        try:
            third_result = self._run_client(AS111_EXTRA_SERVER_IP)
        finally:
            self._print_server_process_list()
            self._print_server_output()
        print("[multihomed] third client output begin")
        print(third_result)
        print("[multihomed] third client output end")

    def _client_command(self, remote_ip):
        remote = f'{AS111_SERVER_IA},{remote_ip}:{SERVER_PORT}'
        return (
            f'test-client -local "{AS112_CLIENT_LOCAL}" '
            f'-remote "{remote}" -expect "{remote}"'
        )

    def _run_client(self, remote_ip):
        return self.dc.execute(
            AS112_CLIENT_CONTAINER,
            "bash",
            "-c",
            self._client_command(remote_ip),
        )

    def _assert_client_failure(self, remote_ip):
        try:
            self._run_client(remote_ip)
        except _CalledProcessErrorWithOutput as err:
            print("[multihomed] observed expected client failure")
            print(err)
            return
        raise AssertionError(f"client unexpectedly succeeded for remote {remote_ip}")

    def _start_server(self):
        self.dc.execute(
            SERVER_CONTAINER,
            "bash",
            "-c",
            "pkill -x test-server || true",
            user="0:0",
        )
        self.dc.execute_detached(
            SERVER_CONTAINER,
            "bash",
            "-c",
            (
                f"test-server -bind 0.0.0.0 -port {SERVER_PORT} "
                "> /proc/1/fd/1 2> /proc/1/fd/2"
            ),
            user="0:0",
        )
        self._wait_for_server_ready()
        print("[multihomed] test-server ready")
        self._print_server_process_list()
        self._print_server_sockets()

    def _wait_for_server_ready(self):
        deadline = time.time() + 10
        while time.time() < deadline:
            if self._server_is_listening():
                return
            time.sleep(0.5)
        raise AssertionError(f"test-server did not start listening on port {SERVER_PORT}")

    def _server_is_listening(self):
        sockets = self._server_socket_list()
        return str(SERVER_PORT) in sockets

    def _server_interfaces_by_ip(self):
        output = self.dc.execute(
            SERVER_CONTAINER,
            "bash",
            "-c",
            "ip -o -4 addr show scope global",
            user="0:0",
        )
        mapping = {}
        for line in output.splitlines():
            fields = line.split()
            if len(fields) < 4:
                continue
            iface = fields[1]
            ip = fields[3].split("/", maxsplit=1)[0]
            mapping[ip] = iface
        for ip in [AS111_INTERNAL_SERVER_IP, AS111_EXTRA_SERVER_IP]:
            if ip not in mapping:
                raise AssertionError(f"server IP {ip} not found in interface list:\n{output}")
        return mapping

    def _ping_br_via_interface(self, interface, br_ip):
        print(f"[multihomed] pinging BR111 address {br_ip} via {interface}")
        print(
            self.dc.execute(
                SERVER_CONTAINER,
                "bash",
                "-c",
                f"ping -I {interface} -c3 {br_ip}",
                user="0:0",
            )
        )

    def _print_server_interfaces(self):
        print(f"[multihomed] interfaces in {SERVER_CONTAINER}")
        print(
            self.dc.execute(
                SERVER_CONTAINER,
                "bash",
                "-c",
                "ip -o addr show || ifconfig -a || cat /proc/net/dev",
                user="0:0",
            )
        )

    def _print_server_routes(self):
        print(f"[multihomed] routes in {SERVER_CONTAINER}")
        print(
            self.dc.execute(
                SERVER_CONTAINER,
                "bash",
                "-c",
                "ip route show || route -n || cat /proc/net/route",
                user="0:0",
            )
        )

    def _print_server_process_list(self):
        print("[multihomed] server process list")
        print(self._server_process_list())

    def _server_process_list(self):
        return self.dc.execute(
            SERVER_CONTAINER,
            "bash",
            "-c",
            "ps -ef | grep test-server | grep -v grep || true",
            user="0:0",
        )

    def _print_server_sockets(self):
        print("[multihomed] server listening sockets")
        print(self._server_socket_list())

    def _server_socket_list(self):
        return self.dc.execute(
            SERVER_CONTAINER,
            "bash",
            "-c",
            f"ss -lunp | grep {SERVER_PORT} || true",
            user="0:0",
        )

    def _print_server_output(self):
        print("[multihomed] test-server captured stdout/stderr (tail=120)")
        print(self.dc("logs", "--tail", "120", SERVER_CONTAINER))


if __name__ == "__main__":
    base.main(Test)
