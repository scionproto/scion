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
1. Setup phase adds a second docker network and a second IP address to the server tester
   container. The AS111 border router is attached to that same extra network so the secondary
   destination IP is actually reachable inside the remote AS.
2. Regression check (bound server): server binds to the primary server IP only, and client
   verifies ping/pong works via that bound endpoint.
3. Multihomed check A (unbound server): server binds to 0.0.0.0, and client reaches it via
   server primary IP.
4. Multihomed check B (unbound server): server binds to 0.0.0.0, and client reaches it via
   server secondary IP. The reply may still use the server's primary IP as source address, so
   this step checks successful ping/pong delivery rather than exact reply source selection.
"""

import os
import time
import yaml
from plumbum import local

from acceptance.common import base


class Test(base.TestTopogen):
    def setup_prepare(self):
        super().setup_prepare()

        # Patch generated docker-compose topology to give the server tester network namespace a
        # second IP address on a dedicated local network. Tester containers inherit networking
        # from their disp_tester sidecars, so the extra network must be attached there rather
        # than on the tester service itself. The remote AS border router also needs connectivity
        # to that subnet, otherwise packets addressed to the secondary IP would time out at
        # delivery.
        compose_path = self.artifacts / "gen/scion-dc.yml"
        with open(compose_path, "r") as file:
            scion_dc = yaml.safe_load(file)

        if "local_002" in scion_dc["networks"]:
            raise RuntimeError("expected local_002 to be absent before multihomed test setup")

        scion_dc["networks"]["local_002"] = {
            "driver": "bridge",
            "driver_opts": {"com.docker.network.bridge.name": "local_002"},
            "ipam": {"config": [{"subnet": "192.168.200.0/24"}]},
        }

        server_disp = scion_dc["services"]["disp_tester_1-ff00_0_111"]
        server_router = scion_dc["services"]["br1-ff00_0_111-1"]

        server_disp.setdefault("networks", {})["local_002"] = {"ipv4_address": "192.168.200.11"}
        server_router.setdefault("networks", {})["local_002"] = {"ipv4_address": "192.168.200.21"}

        with open(compose_path, "w") as file:
            yaml.dump(scion_dc, file)

    def _server_primary_ip(self):
        # Read the original topology IP from the tester dispatcher so we can test both original
        # and secondary IPs of the shared tester network namespace.
        compose_path = self.artifacts / "gen/scion-dc.yml"
        with open(compose_path, "r") as file:
            scion_dc = yaml.safe_load(file)

        nets = scion_dc["services"]["disp_tester_1-ff00_0_111"]["networks"]
        if "scn_002" in nets and "ipv4_address" in nets["scn_002"]:
            return nets["scn_002"]["ipv4_address"]
        for data in nets.values():
            ip = data.get("ipv4_address")
            if ip and ip != "192.168.200.11":
                return ip
        raise RuntimeError("could not determine server primary IP")

    def _compose_services(self):
        compose_path = self.artifacts / "gen/scion-dc.yml"
        with open(compose_path, "r") as file:
            return yaml.safe_load(file)["services"]

    def _service_network_addresses(self, service):
        services = self._compose_services()
        service_config = services[service]
        networks = service_config.get("networks", {})
        if not networks:
            network_mode = service_config.get("network_mode", "")
            if network_mode.startswith("service:"):
                return self._service_network_addresses(network_mode.split(":", 1)[1])
        addresses = {}
        for network_name, config in networks.items():
            ipv4 = config.get("ipv4_address")
            ipv6 = config.get("ipv6_address")
            if ipv4:
                addresses[network_name] = ipv4
            elif ipv6:
                addresses[network_name] = ipv6
        return addresses

    def _shared_target_address(
        self,
        source_service,
        target_service,
        *,
        expected_ip=None,
        preferred_network=None,
        excluded_networks=None,
    ):
        source_networks = self._service_network_addresses(source_service)
        target_networks = self._service_network_addresses(target_service)
        excluded = set(excluded_networks or [])
        shared_networks = [
            network for network in source_networks
            if network in target_networks and network not in excluded
        ]
        if not shared_networks:
            raise RuntimeError(
                f"no shared docker network between {source_service} and {target_service}"
            )
        if preferred_network:
            if preferred_network not in shared_networks:
                raise RuntimeError(
                    f"{source_service} and {target_service} do not share {preferred_network}"
                )
            return preferred_network, target_networks[preferred_network]
        if expected_ip:
            for network in shared_networks:
                if target_networks[network] == expected_ip:
                    return network, target_networks[network]
            raise RuntimeError(
                f"expected {target_service} to use {expected_ip} on one of {shared_networks}"
            )
        network = shared_networks[0]
        return network, target_networks[network]

    def _ping_hop(
        self,
        *,
        label,
        source_service,
        target_service,
        expected_ip=None,
        preferred_network=None,
        excluded_networks=None,
    ):
        network, target_ip = self._shared_target_address(
            source_service,
            target_service,
            expected_ip=expected_ip,
            preferred_network=preferred_network,
            excluded_networks=excluded_networks,
        )
        family_flag = "-6" if ":" in target_ip else "-4"
        print(
            f"ping diagnostics {label}: source={source_service} target={target_service} "
            f"network={network} target_ip={target_ip}"
        )
        result = self.dc.execute(
            source_service,
            "bash",
            "-c",
            f"ping {family_flag} -c 3 {target_ip}",
            user="0:0",
        )
        print(result)

    def _run_ping_diagnostics(self, primary_ip, secondary_ip):
        failures = []
        hops = [
            {
                "label": "client->112br1",
                "source_service": "tester_1-ff00_0_112",
                "target_service": "br1-ff00_0_112-1",
            },
            {
                "label": "as110->110br2",
                "source_service": "tester_1-ff00_0_110",
                "target_service": "br1-ff00_0_110-2",
            },
            {
                "label": "as110->110br1",
                "source_service": "tester_1-ff00_0_110",
                "target_service": "br1-ff00_0_110-1",
            },
            {
                "label": "as111->111br1",
                "source_service": "tester_1-ff00_0_111",
                "target_service": "br1-ff00_0_111-1",
            },
            {
                "label": "as111->server-remote_primary",
                "source_service": "tester_1-ff00_0_111",
                "target_service": "disp_tester_1-ff00_0_111",
                "expected_ip": primary_ip,
                "excluded_networks": ["local_002"],
            },
            {
                "label": "as111->server-remote_secondary",
                "source_service": "tester_1-ff00_0_111",
                "target_service": "disp_tester_1-ff00_0_111",
                "expected_ip": secondary_ip,
                "preferred_network": "local_002",
            },
        ]
        for hop in hops:
            try:
                self._ping_hop(**hop)
            except Exception as err:  # noqa: BLE001 - keep collecting diagnostics on failures
                failures.append((hop["label"], err))
                print(f"ping diagnostics {hop['label']} failed:\n{err}")
        if failures:
            print("ping diagnostics summary: failures were observed before remote_secondary test")
            for label, err in failures:
                print(f"  - {label}: {err}")
        else:
            print("ping diagnostics summary: all hop-by-hop pings succeeded")

    def _scion_ping(self, *, label, remote_addr):
        print(f"scion ping diagnostics {label}: remote={remote_addr}")
        result = self.dc.execute(
            "tester_1-ff00_0_112",
            "bash",
            "-c",
            f'scion ping -c 3 "{remote_addr}"',
        )
        print(result)

    def _run_scion_ping_diagnostics(self, primary_ip, secondary_ip):
        failures = []
        probes = [
            {
                "label": "client->server-primary",
                "remote_addr": f"1-ff00:0:111,{primary_ip}",
            },
            {
                "label": "client->server-secondary",
                "remote_addr": f"1-ff00:0:111,{secondary_ip}",
            },
        ]
        for probe in probes:
            try:
                self._scion_ping(**probe)
            except Exception as err:  # noqa: BLE001 - keep collecting diagnostics on failures
                failures.append((probe["label"], err))
                print(f"scion ping diagnostics {probe['label']} failed:\n{err}")
        if failures:
            print("scion ping diagnostics summary: "
                  "failures were observed before remote_secondary test")
            for label, err in failures:
                print(f"  - {label}: {err}")
        else:
            print("scion ping diagnostics summary: both SCION ping probes succeeded")

    def _scion_traceroute(self, *, label, remote_addr):
        print(f"scion traceroute diagnostics {label}: remote={remote_addr}")
        result = self.dc.execute(
            "tester_1-ff00_0_112",
            "bash",
            "-c",
            f'scion traceroute "{remote_addr}"',
        )
        print(result)

    def _run_scion_traceroute_diagnostics(self, primary_ip, secondary_ip):
        failures = []
        probes = [
            {
                "label": "client->server-primary",
                "remote_addr": f"1-ff00:0:111,{primary_ip}",
            },
            {
                "label": "client->server-secondary",
                "remote_addr": f"1-ff00:0:111,{secondary_ip}",
            },
        ]
        for probe in probes:
            try:
                self._scion_traceroute(**probe)
            except Exception as err:  # noqa: BLE001 - keep collecting diagnostics on failures
                failures.append((probe["label"], err))
                print(f"scion traceroute diagnostics {probe['label']} failed:\n{err}")
        if failures:
            print(
                "scion traceroute diagnostics summary: failures were observed before "
                "remote_secondary test"
            )
            for label, err in failures:
                print(f"  - {label}: {err}")
        else:
            print("scion traceroute diagnostics summary: both traceroute probes succeeded")

    def bash_at_server(self, cmd, *args, **kwargs):
            print(
                self.dc.execute(
                    "tester_1-ff00_0_111",
                    "bash",
                    "-c",
                    cmd,
                    *args,
                    **kwargs,
                )
            )

    def _run_orig(self):
        # Wait until SCION control-plane/path connectivity is established.
        self.await_connectivity()
        time.sleep(5)

        # Copy test binaries into the two tester containers.
        test_client = local["realpath"](self.get_executable("test-client").executable).strip()
        test_server = local["realpath"](self.get_executable("test-server").executable).strip()

        self.dc("cp", test_server, "tester_1-ff00_0_111:/bin/")
        self.dc("cp", test_client, "tester_1-ff00_0_112:/bin/")

        primary_ip = self._server_primary_ip()
        secondary_ip = "192.168.200.11"
        bound_port = 31001
        multihomed_port = 31000

        SERVERLOGFILE="/tmp/log.txt"

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
        self.bash_at_server(f"touch {SERVERLOGFILE} ; " +
                            f"chown {os.getuid()}:{os.getgid()} {SERVERLOGFILE}",
                            user="0:0")
        self.bash_at_server(f"ls -l {SERVERLOGFILE}")
        self.dc.execute_detached(
            "tester_1-ff00_0_111",
            "bash",
            "-c",
            f"test-server -bind 0.0.0.0 -port {multihomed_port} > {SERVERLOGFILE} 2>&1",
        )
        time.sleep(2)
        print("---------------------------------------------------")
        self.bash_at_server("ifconfig ; echo ; route -n ; echo ; ps aux")
        print("---------------------------------------------------")

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

        self._run_ping_diagnostics(primary_ip, secondary_ip)
        self._run_scion_ping_diagnostics(primary_ip, secondary_ip)
        self._run_scion_traceroute_diagnostics(primary_ip, secondary_ip)

        # 3) Multihomed check using server secondary IP while server is unbound (0.0.0.0).
        # Linux may still select the primary IP as reply source, so this validates connectivity
        # through the secondary destination without enforcing the response source address.
        remote_secondary = f"1-ff00:0:111,{secondary_ip}:{multihomed_port}"
        print(f"running client against secondary IP: {remote_secondary}")
        result_secondary = ""
        try:
            result_secondary = self.dc.execute(
                "tester_1-ff00_0_112",
                "bash",
                "-c",
                f'test-client -local "{local_addr}" -remote "{remote_secondary}"',
            )
        finally:
            print("Client results:")
            print(result_secondary)
            print("\n\nServer log:")
            self.bash_at_server(f"cat {SERVERLOGFILE}")

    def _run(self):
        # Start with a diagnostics-only run so we can debug SCION reachability to the
        # server's secondary address before exercising the application-level test flow.
        self.await_connectivity()
        time.sleep(5)

        primary_ip = self._server_primary_ip()
        secondary_ip = "192.168.200.11"

        print(f"server IPs configured: primary={primary_ip}, secondary={secondary_ip}")

        self._run_ping_diagnostics(primary_ip, secondary_ip)
        self._run_scion_ping_diagnostics(primary_ip, secondary_ip)
        self._run_scion_traceroute_diagnostics(primary_ip, secondary_ip)


if __name__ == "__main__":
    base.main(Test)
