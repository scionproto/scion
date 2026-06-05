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
   verifies ping/pong works via that bound endpoint.
3. Multihomed check A (unbound server): server binds to 0.0.0.0, and client reaches it via
   server primary IP.
4. Multihomed check B (unbound server): server binds to 0.0.0.0, and client reaches it via
   server secondary IP. The reply may still use the server's primary IP as source address, so
   this step checks successful ping/pong delivery rather than exact reply source selection.
"""

import os
import ipaddress
import subprocess
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

    def setup_start(self):
        super().setup_start()
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

    def _server_primary_ip(self):
        return self._server_network_info()["primary_ip"]

    def _server_secondary_ip(self):
        return self._server_network_info()["secondary_ip"]

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
        server_network = self._server_network_info()
        interface = self._server_interface(server_network["primary_ip"])
        secondary_cidr = (
            f"{server_network['secondary_ip']}/{server_network['prefix_len']}"
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
        target_ip=None,
        expected_ip=None,
        preferred_network=None,
        excluded_networks=None,
    ):
        if target_ip:
            return preferred_network or "explicit", target_ip
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
        target_ip=None,
        expected_ip=None,
        preferred_network=None,
        excluded_networks=None,
    ):
        network, target_ip = self._shared_target_address(
            source_service,
            target_service,
            target_ip=target_ip,
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
        server_network = self._server_network_info()
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
                "target_ip": primary_ip,
                "preferred_network": server_network["network"],
            },
            {
                "label": "as111->server-remote_secondary",
                "source_service": "tester_1-ff00_0_111",
                "target_service": "disp_tester_1-ff00_0_111",
                "target_ip": secondary_ip,
                "preferred_network": server_network["network"],
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

    def _start_server_capture(self, capture_file, capture_log_file, pid_file):
        self.dc.execute_detached(
            "tester_1-ff00_0_111",
            "bash",
            "-c",
            (
                f"rm -f {capture_file} {capture_log_file} {pid_file} ; "
                f"tshark -q -n -i any "
                f"-w {capture_file} > {capture_log_file} 2>&1 & "
                f"echo $! > {pid_file}"
            ),
            user="0:0",
        )

    def _stop_server_capture(self, pid_file):
        self.dc.execute(
            "tester_1-ff00_0_111",
            "bash",
            "-c",
            (
                f"if [ -f {pid_file} ]; then "
                f"kill $(cat {pid_file}) 2>/dev/null || true ; "
                f"wait $(cat {pid_file}) 2>/dev/null || true ; "
                f"fi"
            ),
            user="0:0",
        )

    def _collect_server_capture_artifacts(self, *container_files):
        capture_dir = self._capture_artifact_dir()
        os.makedirs(capture_dir, exist_ok=True)
        for container_file in container_files:
            try:
                self.dc(
                    "cp",
                    f"tester_1-ff00_0_111:{container_file}",
                    str(capture_dir / os.path.basename(container_file)),
                )
            except Exception as err:  # noqa: BLE001 - capture export should not fail the test
                print(f"warning: failed to export capture artifact {container_file}: {err}")

    def _capture_artifact_dir(self):
        return self.artifacts / "logs/server-capture"

    def _write_host_artifact(self, filename, content):
        capture_dir = self._capture_artifact_dir()
        os.makedirs(capture_dir, exist_ok=True)
        output_path = capture_dir / filename
        with open(output_path, "w", encoding="utf-8") as file:
            file.write(content)
        return output_path

    def _run_host_debug_dump(self, *, title, filename, command):
        print(f"\n\n{title}:")
        try:
            result = subprocess.run(
                command,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                encoding="utf-8",
            )
            output = result.stdout
            self._write_host_artifact(filename, output)
            print(output)
            if result.returncode != 0:
                print(
                    f"warning: {title} exited with status {result.returncode}; "
                    "captured output anyway"
                )
        except Exception as err:  # noqa: BLE001 - debug output should not fail the test
            print(f"warning: failed to collect {title}: {err}")

    def _docker_compose_container_id(self, service):
        compose_file = str(self.artifacts / "gen/scion-dc.yml")
        result = subprocess.run(
            ["docker", "compose", "-f", compose_file, "ps", "-q", service],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            encoding="utf-8",
        )
        container_id = result.stdout.strip()
        if not container_id:
            raise RuntimeError(f"could not determine container ID for {service}")
        return container_id

    def _inspect_docker_network_for_service(self, *, service, network_name, filename_prefix):
        try:
            container_id = self._docker_compose_container_id(service)
            inspect_result = subprocess.run(
                ["docker", "inspect", container_id],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
            )
            self._write_host_artifact(
                f"{filename_prefix}-container-inspect.json",
                inspect_result.stdout,
            )
            network_result = subprocess.run(
                ["docker", "network", "inspect", network_name],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
            )
            self._write_host_artifact(
                f"{filename_prefix}-network-inspect.json",
                network_result.stdout,
            )
            print(
                f"docker network diagnostics {service}: "
                f"container_id={container_id} network={network_name}"
            )
        except Exception as err:  # noqa: BLE001 - debug output should not fail the test
            print(f"warning: failed to inspect docker network for {service}: {err}")

    def _run_debug_dump(self, *, service, title, output_file, command, shell="bash"):
        print(f"\n\n{title}:")
        try:
            self.dc.execute(
                service,
                shell,
                "-c",
                f"{command} > {output_file}",
                user="0:0",
            )
            output = self.dc.execute(
                service,
                shell,
                "-c",
                f"cat {output_file}",
                user="0:0",
            )
            print(output)
            self._collect_server_capture_artifacts(output_file)
        except Exception as err:  # noqa: BLE001 - debug output should not fail the test
            print(f"warning: failed to collect {title}: {err}")

    def _print_server_network_diagnostics(self):
        dumps = [
            {
                "service": "tester_1-ff00_0_111",
                "title": "Server namespace ip addr",
                "output_file": "/tmp/server-ip-addr.txt",
                "command": "ip addr",
            },
            {
                "service": "tester_1-ff00_0_111",
                "title": "Server namespace ip route",
                "output_file": "/tmp/server-ip-route.txt",
                "command": "ip route",
            },
            {
                "service": "tester_1-ff00_0_111",
                "title": "Server namespace ip rule",
                "output_file": "/tmp/server-ip-rule.txt",
                "command": "ip rule",
            },
            {
                "service": "tester_1-ff00_0_111",
                "title": "Server namespace UDP sockets",
                "output_file": "/tmp/server-ss-lunp.txt",
                "command": "ss -lunp",
            },
            {
                "service": "tester_1-ff00_0_111",
                "title": "Server namespace ip neigh",
                "output_file": "/tmp/server-ip-neigh.txt",
                "command": "ip neigh",
            },
        ]
        for dump in dumps:
            self._run_debug_dump(**dump)

    def _print_router_network_diagnostics(self):
        dumps = [
            {
                "service": "br1-ff00_0_111-1",
                "title": "Router namespace ip addr",
                "output_file": "/tmp/router-ip-addr.txt",
                "command": "ip addr",
                "shell": "sh",
            },
            {
                "service": "br1-ff00_0_111-1",
                "title": "Router namespace ip route",
                "output_file": "/tmp/router-ip-route.txt",
                "command": "ip route",
                "shell": "sh",
            },
            {
                "service": "br1-ff00_0_111-1",
                "title": "Router namespace ip rule",
                "output_file": "/tmp/router-ip-rule.txt",
                "command": "ip rule",
                "shell": "sh",
            },
            {
                "service": "br1-ff00_0_111-1",
                "title": "Router namespace UDP sockets",
                "output_file": "/tmp/router-ss-lunp.txt",
                "command": "ss -lunp",
                "shell": "sh",
            },
            {
                "service": "br1-ff00_0_111-1",
                "title": "Router namespace ip neigh",
                "output_file": "/tmp/router-ip-neigh.txt",
                "command": "ip neigh",
                "shell": "sh",
            },
        ]
        for dump in dumps:
            self._run_debug_dump(**dump)

    def _print_host_network_diagnostics(self, secondary_ip):
        server_network = self._server_network_info()
        bridge_name = server_network["network"]
        dumps = [
            {
                "title": f"Host {bridge_name} ip addr",
                "filename": f"host-{bridge_name}-ip-addr.txt",
                "command": ["ip", "addr", "show", "dev", bridge_name],
            },
            {
                "title": f"Host {bridge_name} ip route",
                "filename": f"host-{bridge_name}-ip-route.txt",
                "command": ["ip", "route", "show", "dev", bridge_name],
            },
            {
                "title": f"Host {bridge_name} bridge fdb",
                "filename": f"host-{bridge_name}-bridge-fdb.txt",
                "command": ["bridge", "fdb", "show", "dev", bridge_name],
            },
            {
                "title": f"Host {bridge_name} ip neigh",
                "filename": f"host-{bridge_name}-ip-neigh.txt",
                "command": ["ip", "neigh", "show", "dev", bridge_name],
            },
        ]
        for dump in dumps:
            self._run_host_debug_dump(**dump)
        self._run_debug_dump(
            service="tester_1-ff00_0_111",
            title="Server namespace secondary-ip neigh probe",
            output_file="/tmp/server-secondary-ip-neigh.txt",
            command=f"ip neigh show to {secondary_ip}",
        )
        self._inspect_docker_network_for_service(
            service=self.SERVER_SERVICE,
            network_name=bridge_name,
            filename_prefix="host-server-secondary",
        )
        self._inspect_docker_network_for_service(
            service=self.SERVER_ROUTER_SERVICE,
            network_name=bridge_name,
            filename_prefix="host-router-secondary",
        )

    def _print_server_capture(self, capture_file, capture_log_file, summary_file, all_packets_file):
        self.bash_at_server(
            (
                f"tshark -r {capture_file} -n "
                f"-Y 'arp or icmp or udp.port==30041 or udp.port==30042' "
                f"> {summary_file}"
            ),
            user="0:0",
        )
        self.bash_at_server(
            f"tshark -r {capture_file} -n > {all_packets_file}",
            user="0:0",
        )
        self._collect_server_capture_artifacts(
            capture_file,
            capture_log_file,
            summary_file,
            all_packets_file,
        )
        print("\n\nServer packet capture startup log:")
        self.bash_at_server(f"cat {capture_log_file}", user="0:0")
        print("\n\nServer packet capture summary:")
        self.bash_at_server(f"cat {summary_file}", user="0:0")
        print(
            "\n\nServer capture artifacts copied to "
            f"{self.artifacts / 'logs/server-capture'}"
        )
        self._print_server_network_diagnostics()
        self._print_router_network_diagnostics()
        self._print_host_network_diagnostics(self._server_secondary_ip())

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

    def _run(self):
        # Wait until SCION control-plane/path connectivity is established.
        self.await_connectivity()
        time.sleep(5)

        # Copy test binaries into the two tester containers.
        test_client = local["realpath"](self.get_executable("test-client").executable).strip()
        test_server = local["realpath"](self.get_executable("test-server").executable).strip()

        self.dc("cp", test_server, "tester_1-ff00_0_111:/bin/")
        self.dc("cp", test_client, "tester_1-ff00_0_112:/bin/")

        primary_ip = self._server_primary_ip()
        secondary_ip = self._server_secondary_ip()
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

        # self._run_ping_diagnostics(primary_ip, secondary_ip)
        # self._run_scion_ping_diagnostics(primary_ip, secondary_ip)
        # self._run_scion_traceroute_diagnostics(primary_ip, secondary_ip)

        # 3) Multihomed check using server secondary IP while server is unbound (0.0.0.0).
        # Linux may still select the primary IP as reply source, so this validates connectivity
        # through the secondary destination without enforcing the response source address.
        remote_secondary = f"1-ff00:0:111,{secondary_ip}:{multihomed_port}"
        print(f"running client against secondary IP: {remote_secondary}")
        # result_secondary = ""
        # try:
        #     result_secondary = self.dc.execute(
        #         "tester_1-ff00_0_112",
        #         "bash",
        #         "-c",
        #         f'test-client -local "{local_addr}" -remote "{remote_secondary}"',
        #     )
        # finally:
        #     print("Client results:")
        #     print(result_secondary)
        #     print("\n\nServer log:")
        #     self.bash_at_server(f"cat {SERVERLOGFILE}")
        result_secondary = self.dc.execute(
            "tester_1-ff00_0_112",
            "bash",
            "-c",
            f'test-client -local "{local_addr}" -remote "{remote_secondary}"',
        )
        print(result_secondary)

    # def _run_diagnosis(self):
    #     # Start with a diagnostics-only run so we can debug SCION reachability to the
    #     # server's secondary address before exercising the application-level test flow.
    #     self.await_connectivity()
    #     time.sleep(5)

    #     primary_ip = self._server_primary_ip()
    #     secondary_ip = self._server_secondary_ip()
    #     capture_file = "/tmp/server-capture.pcapng"
    #     capture_log_file = "/tmp/server-capture.log"
    #     pid_file = "/tmp/server-capture.pid"
    #     summary_file = "/tmp/server-capture-summary.txt"
    #     all_packets_file = "/tmp/server-capture-all.txt"

    #     print(f"server IPs configured: primary={primary_ip}, secondary={secondary_ip}")
    #     self._start_server_capture(capture_file, capture_log_file, pid_file)
    #     try:
    #         self._run_ping_diagnostics(primary_ip, secondary_ip)
    #         self._run_scion_ping_diagnostics(primary_ip, secondary_ip)
    #         self._run_scion_traceroute_diagnostics(primary_ip, secondary_ip)
    #     finally:
    #         self._stop_server_capture(pid_file)
    #         self._print_server_capture(
    #             capture_file,
    #             capture_log_file,
    #             summary_file,
    #             all_packets_file,
    #         )


if __name__ == "__main__":
    base.main(Test)
