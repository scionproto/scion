#!/usr/bin/env python3

# Copyright 2020 Anapaya Systems
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

import json
import re
import time
import yaml
from http import client

from acceptance.common import base
from acceptance.common import docker
from acceptance.common import scion


class Test(base.TestBase):

    def main(self):
        print("artifacts dir: %s" % self.test_state.artifacts)
        self._unpack_topo()
        if not self.nested_command:
            try:
                self.setup()
                self._run()
            finally:
                self.teardown()

    def _refresh_paths(self):
        self.test_state.dc("exec", "-T", "tester_1-ff00_0_110", "ping", "-c", "2",
                           "172.20.0.39")
        self.test_state.dc("exec", "-T", "tester_1-ff00_0_111", "ping", "-c", "2",
                           "172.20.0.23")
        self.test_state.dc("exec", "-T", "tester_1-ff00_0_110", "scion", "sp", "1-ff00:0:111",
                           "--timeout", "5s", "--refresh", "--no-probe")
        self.test_state.dc("exec", "-T", "tester_1-ff00_0_111", "scion", "sp", "1-ff00:0:110",
                           "--timeout", "5s", "--refresh", "--no-probe")

    def _set_path_count(self, path_count):
        # Change the gateway config.
        config_name = self.test_state.artifacts / "gen" / "ASff00_0_111" / "sig.json"
        with open(config_name, "r") as f:
            t = json.load(f)
        t["ASes"]["1-ff00:0:110"]["PathCount"] = path_count
        with open(config_name, "w") as f:
            json.dump(t, f, indent=2)
        # Reload the config.
        self.test_state.dc("kill", "-s", "SIGHUP", "scion_sig_1-ff00_0_111")
        # Give gateway some time to start using the new path count.
        time.sleep(2)

    def _transfer(self, filename, size):
        print("transferring a file (%d MB)" % size)
        # Create a large file.
        self.test_state.dc("exec", "-T", "tester_1-ff00_0_111",
                           "fallocate", "-l", "%dM" % size, filename)
        start_time = time.time()
        # Copy it, via ports 40000-40020, to the other AS.
        self.test_state.dc("exec", "-T", "tester_1-ff00_0_111",
                           "bbcp", "-s",  "20", "-Z", "40000:40020",
                           "localhost:/share/%s" % filename, "172.20.0.23:/share")
        elapsed = time.time() - start_time
        throughput = float(size * 1024 * 1024 * 8) / 1000000 / elapsed
        print("transfer finished")
        print("time elapsed: %f seconds" % elapsed)
        print("throughput: %f mbps" % throughput)

    def _get_br_traffic(self, endpoint):
        conn = client.HTTPConnection(endpoint)
        conn.request('GET', '/metrics')
        resp = conn.getresponse()
        metrics = resp.read().decode('utf-8')
        for line in metrics.splitlines():
            m = re.search(r"""^router_input_bytes_total{interface="internal".*\s(.*)$""", line)
            if m is not None:
                return float(m.group(1)) / 1024 / 1024
        return None

    def setup(self):
        print("setting up the infrastructure")

        self.setup_prepare()

        # Add throttling to the inter-AS links.
        scion_dc = self.test_state.artifacts / "gen/scion-dc.yml"
        with open(scion_dc, "r") as file:
            dc = yaml.load(file, Loader=yaml.FullLoader)
        dc["services"]["tc_setup"] = {
            "container_name": "tc_setup",
            "image": "tester:latest",
            "cap_add": ["NET_ADMIN"],
            "entrypoint": ["/bin/sh", "-ec",
                           "/share/tc_setup.sh scn_000 16.0mbit ;"
                           " /share/tc_setup.sh scn_001 16.0mbit"],
            "depends_on": ["scion_br1-ff00_0_111-1", "scion_br1-ff00_0_111-2"],
            "network_mode": "host",
        }
        with open(scion_dc, "w") as file:
            yaml.dump(dc, file)

        # Start the topology
        self.setup_start()

        # Initialize SSH in tester containers (needed by bbcp)
        self.test_state.dc("exec", "-T", "tester_1-ff00_0_110", "/bin/bash",
                           "/share/ssh_setup.sh")
        self.test_state.dc("exec", "-T", "tester_1-ff00_0_111", "/bin/bash",
                           "/share/ssh_setup.sh")

        # Wait till everything starts working.
        print("waiting for 30 seconds for the system to bootstrap")
        time.sleep(30)
        self._refresh_paths()

        print("setup done")

    def _run(self):
        traffic1 = self._get_br_traffic("172.20.0.34:30442")
        traffic2 = self._get_br_traffic("172.20.0.35:30442")
        print("--------------------")
        print("using one path")
        self._set_path_count(1)
        self._transfer("foo1.txt", 20)
        traffic1 = self._get_br_traffic("172.20.0.34:30442") - traffic1
        print("traffic on path 1: %f MB (includes SCION and encapsulation overhead)" % traffic1)
        traffic2 = self._get_br_traffic("172.20.0.35:30442") - traffic2
        print("traffic on path 2: %f MB (includes SCION and encapsulation overhead)" % traffic2)
        print("--------------------")
        print("using two paths")
        self._set_path_count(2)
        self._transfer("foo2.txt", 20)
        traffic1 = self._get_br_traffic("172.20.0.34:30442") - traffic1
        print("traffic on path 1: %f MB (includes SCION and encapsulation overhead)" % traffic1)
        traffic2 = self._get_br_traffic("172.20.0.35:30442") - traffic2
        print("traffic on path 2: %f MB (includes SCION and encapsulation overhead)" % traffic2)


if __name__ == "__main__":
    base.register_commands(Test)
    Test.test_state = base.TestState(scion.SCIONDocker(), docker.Compose())
    Test.run()
