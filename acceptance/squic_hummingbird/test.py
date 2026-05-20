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

import ipaddress
import time

from acceptance.common import base
from plumbum import local


def scion_udp_addr(ia: str, host: str, port: int) -> str:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None and ip.version == 6:
        return f"{ia},[{host}]:{port}"
    return f"{ia},{host}:{port}"


class Test(base.TestTopogen):
    def setup_start(self):
        super().setup_start()
        self.await_connectivity(timeout_seconds=60)

    def _run(self):
        print("-------------------- running squic_hummingbird test")
        helper_bin = local["realpath"](self.get_executable("squic-hummingbird").executable).strip()
        self.dc("cp", helper_bin, "tester_1-ff00_0_111:/bin/")
        self.dc("cp", helper_bin, "tester_1-ff00_0_112:/bin/")

        server_daemon = self._env("tester_1-ff00_0_111", "SCION_DAEMON")
        server_host = self._env("tester_1-ff00_0_111", "SCION_LOCAL_ADDR")
        client_daemon = self._env("tester_1-ff00_0_112", "SCION_DAEMON")
        client_host = self._env("tester_1-ff00_0_112", "SCION_LOCAL_ADDR")

        server_local = scion_udp_addr("1-ff00:0:111", server_host, 12345)
        client_local = scion_udp_addr("1-ff00:0:112", client_host, 0)
        server_remote = scion_udp_addr("1-ff00:0:111", server_host, 12345)

        self.dc.execute_detached(
            "tester_1-ff00_0_111",
            "bash",
            "-lc",
            f"squic-hummingbird server --daemon '{server_daemon}' --local '{server_local}' "
            "--peer-ia '1-ff00:0:112' --timeout 15s",
        )
        time.sleep(3)

        result = self.dc.execute(
            "tester_1-ff00_0_112",
            "bash",
            "-lc",
            f"squic-hummingbird client --daemon '{client_daemon}' --local '{client_local}' "
            f"--remote '{server_remote}' --keys-root /share/gen --timeout 15s",
        )
        print(result)
        print("-------------------- finished squic_hummingbird test")

    def _env(self, container: str, name: str) -> str:
        return self.dc.execute(container, "printenv", name).strip()


if __name__ == "__main__":
    base.main(Test)
