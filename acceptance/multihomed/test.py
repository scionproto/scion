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
   container. The client tester and the AS111 border router are attached to that same extra
   network so the secondary destination IP is actually reachable inside the remote AS.
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

        # Patch generated docker-compose topology to give the tester network namespaces a second
        # IP address on a dedicated local network. Tester containers inherit networking from their
        # disp_tester sidecars, so the extra network must be attached there rather than on the
        # tester services themselves. The remote AS border router also needs connectivity to that
        # subnet, otherwise packets addressed to the secondary IP would time out at delivery.
        compose_path = self.artifacts / "gen/scion-dc.yml"
        with open(compose_path, "r") as file:
            scion_dc = yaml.safe_load(file)

        scion_dc["networks"]["local_002"] = {
            "driver": "bridge",
            "ipam": {"config": [{"subnet": "192.168.200.0/24"}]},
        }

        server_disp = scion_dc["services"]["disp_tester_1-ff00_0_111"]
        client_disp = scion_dc["services"]["disp_tester_1-ff00_0_112"]
        server_router = scion_dc["services"]["br1-ff00_0_111-1"]

        server_disp.setdefault("networks", {})["local_002"] = {"ipv4_address": "192.168.200.11"}
        client_disp.setdefault("networks", {})["local_002"] = {"ipv4_address": "192.168.200.12"}
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
        secondary_ip = "192.168.200.11"
        bound_port = 31001
        multihomed_port = 31000

        # SERVERLOGFILE="/tmp/log.txt"

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


        def bash_at_server(cmd, *args, **kwargs):
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

        # # bash(f"ls -l / ; echo ; ls -l /tmp ; echo ; ls -l /share")
        # # bash("whoami ; id")
        # bash_at_server(f"touch {SERVERLOGFILE} ; " +
        #                f"chown {os.getuid()}:{os.getgid()} {SERVERLOGFILE}",
        #                user="0:0")
        # # bash(f"ls -l {LOGFILE}")


        # 2) Multihomed check using server primary IP while server is unbound (0.0.0.0).
        self.dc.execute_detached(
            "tester_1-ff00_0_111",
            "bash",
            "-c",
            # f"test-server -bind 0.0.0.0 -port {multihomed_port} > {SERVERLOGFILE} 2>&1",
            f"test-server -bind 0.0.0.0 -port {multihomed_port}",
        )
        time.sleep(2)
        print("---------------------------------------------------")
        bash_at_server(f"ifconfig ; echo -e '\n\n' ; route -n")
        print("---------------------------------------------------")

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




        # print("bringing one interface down at the server")
        # print("---------------------------------------------------")
        # # bash_at_server(f"ifconfig eth1 down ; echo 'removed eth0' ; sleep 2 ; " +
        # #      "ifconfig ; echo -n '\n' ; route -n", user="0:0")
        # bash_at_server(f"ip addr del 192.168.200.11/24 dev eth1 ; sleep 1 ; ifconfig ; route -n",
        #                user="0:0")
        # print("---------------------------------------------------")
        # # Give docker some time to bring down the interface in the container.
        # time.sleep(5)









if __name__ == "__main__":
    base.main(Test)
