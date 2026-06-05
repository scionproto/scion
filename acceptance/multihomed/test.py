#!/usr/bin/env python3

# Copyright 2025 ETH Zurich
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

"""
Acceptance test for SCION multihomed socket behavior.

Manual run (single command):
  bazel test --config=integration //acceptance/multihomed:test --test_output=streamed

Manual run in phases (useful for debugging):
  bazel run //acceptance/multihomed:test_setup
  bazel run //acceptance/multihomed:test_run
  bazel run //acceptance/multihomed:test_teardown

Validation steps:
1. Setup phase adds a second IP address to the server tester container on the existing subnet
   shared with the AS111 border router, so the secondary destination IP remains reachable inside
   the remote AS without creating an extra docker network.
2. Regression check (bound server): server binds to the primary server IP only, and client
   verifies request/response traffic works via that bound endpoint.
3. Multihomed check A (unbound server): server binds to 0.0.0.0, and client reaches it via
   server primary IP.
4. Multihomed check B (unbound server): server binds to 0.0.0.0, and client reaches it via
   server secondary IP. The reply may still use the server's primary IP as source address, so
   this step checks successful request/response delivery rather than exact reply source selection.
"""

import ipaddress
import time
import yaml
from plumbum import local

from acceptance.common import base


class Test(base.TestTopogen):
    SERVER_PRIMARY_NETWORK = "scn_002"
    SERVER_SERVICE = "disp_tester_1-ff00_0_111"
    SERVER_ROUTER_SERVICE = "br1-ff00_0_111-1"

    def setup_prepare(self):
        super().setup_prepare()
        # Keep the generated topology unchanged. We add the secondary server IP after the
        # containers are up so the test uses the existing subnet shared with 111-br1 instead of
        # creating an extra docker bridge that has proven flaky in CI.
        self._server_network = None  # Filled up in setup_start()

    def setup_start(self):
        super().setup_start()
        self._server_network = self._server_network_info()
        self._configure_server_secondary_ip()

    def _server_network_info(self):
        compose_path = self.artifacts / "gen/scion-dc.yml"
        with open(compose_path, "r") as file:
            scion_dc = yaml.safe_load(file)

        networks = scion_dc["networks"]
        services = scion_dc["services"]
        server_networks = services[self.SERVER_SERVICE]["networks"]
        router_networks = services[self.SERVER_ROUTER_SERVICE]["networks"]

        if self.SERVER_PRIMARY_NETWORK not in server_networks:
            raise RuntimeError(
                f"expected {self.SERVER_SERVICE} to be attached to {self.SERVER_PRIMARY_NETWORK}"
            )
        if self.SERVER_PRIMARY_NETWORK not in router_networks:
            raise RuntimeError(
                f"expected {self.SERVER_ROUTER_SERVICE} to be attached to {self.SERVER_PRIMARY_NETWORK}"
            )

        network_cfg = networks[self.SERVER_PRIMARY_NETWORK]["ipam"]["config"]
        ipv4_subnet = next(
            (entry["subnet"] for entry in network_cfg if "." in entry["subnet"]),
            None,
        )
        if not ipv4_subnet:
            raise RuntimeError(f"could not determine IPv4 subnet for {self.SERVER_PRIMARY_NETWORK}")

        primary_ip = server_networks[self.SERVER_PRIMARY_NETWORK]["ipv4_address"]
        router_ip = router_networks[self.SERVER_PRIMARY_NETWORK]["ipv4_address"]
        subnet = ipaddress.ip_network(ipv4_subnet, strict=True)
        gateway_ip = str(next(subnet.hosts()))
        used = {
            service_network.get("ipv4_address")
            for service in services.values()
            for service_network in service.get("networks", {}).values()
            if service_network.get("ipv4_address")
        }
        used.add(gateway_ip)
        secondary_ip = None
        for host in subnet.hosts():
            host_ip = str(host)
            if host_ip not in used:
                secondary_ip = host_ip
                break
        if not secondary_ip:
            raise RuntimeError(f"could not find a free address in {subnet}")

        return {
            "network": self.SERVER_PRIMARY_NETWORK,
            "subnet": ipv4_subnet,
            "prefix_len": subnet.prefixlen,
            "primary_ip": primary_ip,
            "router_ip": router_ip,
            "gateway_ip": gateway_ip,
            "secondary_ip": secondary_ip,
        }

    def _server_interface(self, expected_ip):
        output = self.dc.execute(
            "tester_1-ff00_0_111",
            "bash",
            "-c",
            "ip -o -4 addr show",
            user="0:0",
        )
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 4 and fields[3].split("/", 1)[0] == expected_ip:
                return fields[1]
        raise RuntimeError(f"could not determine interface for {expected_ip}")

    def _configure_server_secondary_ip(self):
        interface = self._server_interface(self._server_network["primary_ip"])
        secondary_cidr = (
            f"{self._server_network['secondary_ip']}/{self._server_network['prefix_len']}"
        )
        self.dc.execute(
            "tester_1-ff00_0_111",
            "bash",
            "-c",
            (
                f"ip addr add {secondary_cidr} dev {interface} 2>/dev/null || "
                f"ip addr replace {secondary_cidr} dev {interface}"
            ),
            user="0:0",
        )

    def _run(self):
        # Wait until SCION control-plane/path connectivity is established.
        self.await_connectivity()
        time.sleep(5)

        # Copy test binaries into the two tester containers.
        test_client = local["realpath"](self.get_executable("test-client").executable).strip()
        test_server = local["realpath"](self.get_executable("test-server").executable).strip()

        self.dc("cp", test_server, "tester_1-ff00_0_111:/bin/")
        self.dc("cp", test_client, "tester_1-ff00_0_112:/bin/")

        primary_ip = self._server_network["primary_ip"]
        secondary_ip = self._server_network["secondary_ip"]
        bound_port = 31001
        multihomed_port = 31000

        print(f"server IPs configured: primary={primary_ip}, secondary={secondary_ip}")

        # 1) Regression check: bound server must still work with a specific IP binding.
        self.dc.execute_detached(
            "tester_1-ff00_0_111",
            "bash",
            "-c",
            f"test-server -bind {primary_ip} -port {bound_port}",
        )
        time.sleep(2)

        local_addr = "1-ff00:0:112,0.0.0.0:0"
        remote_bound = f"1-ff00:0:111,{primary_ip}:{bound_port}"
        print(f"running bound-address regression scenario: {remote_bound}")
        result_bound = self.dc.execute(
            "tester_1-ff00_0_112",
            "bash",
            "-c",
            f'test-client -local "{local_addr}" -remote "{remote_bound}" '
            f'-expect "{remote_bound}"',
        )
        print(result_bound)

        # Kill server.
        print("killing server (SIGKILL) bound to one IP")
        self.dc.execute_detached(
            "tester_1-ff00_0_111",
            "bash",
            "-c",
            f"killall -9 test-server",
        )
        print("server terminated successfully")
        time.sleep(2)

        # Multihomed server.
        self.dc.execute_detached(
            "tester_1-ff00_0_111",
            "bash",
            "-c",
            f"test-server -bind 0.0.0.0 -port {multihomed_port}",
        )
        time.sleep(2)

        # 2) Multihomed check using server primary IP while server is unbound (0.0.0.0).
        remote_primary = f"1-ff00:0:111,{primary_ip}:{multihomed_port}"
        print(f"running client against primary IP: {remote_primary}")
        result_primary = self.dc.execute(
            "tester_1-ff00_0_112",
            "bash",
            "-c",
            f'test-client -local "{local_addr}" -remote "{remote_primary}" '
            f'-expect "{remote_primary}"',
        )
        print(result_primary)

        # 3) Multihomed check using server secondary IP while server is unbound (0.0.0.0).
        # Linux may still select the primary IP as reply source, so this validates connectivity
        # through the secondary destination without enforcing the response source address.
        remote_secondary = f"1-ff00:0:111,{secondary_ip}:{multihomed_port}"
        print(f"running client against secondary IP: {remote_secondary}")

        result_secondary = self.dc.execute(
            "tester_1-ff00_0_112",
            "bash",
            "-c",
            f'test-client -local "{local_addr}" -remote "{remote_secondary}"',
        )
        print(result_secondary)

if __name__ == "__main__":
    base.main(Test)
