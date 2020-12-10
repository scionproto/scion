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
import logging
import time
import yaml

from plumbum import cmd

from acceptance.common import base
from acceptance.common import log
from acceptance.common import tools
from acceptance.common import scion


base.set_name(__file__)
logger = logging.getLogger(__name__)


class Test(base.TestBase):

    def main(self):
        print("artifacts dir: %s" % self.test_state.artifacts)
        self._unpack_topo()
        if not self.nested_command:
            try:
                self._setup()
                self._run()
            finally:
                self._teardown()

    def _unpack_topo(self):
        # Unpack the topogen output.
        cmd.tar("-xf", "./demo/file_transfer/gen.tar",
                "-C", self.test_state.artifacts)
        # Adjust SCIONROOT.
        scion_dc = self.test_state.artifacts / "gen/scion-dc.yml"
        cmd.sed("-i", "s#$SCIONROOT#%s#g" % self.test_state.artifacts, scion_dc)
        # Add throttling to the inter-AS links.
        with open(scion_dc, "r") as file:
            dc = yaml.load(file, Loader=yaml.FullLoader)
        dc["services"]["tc_setup"] = {
            "container_name": "tc_setup",
            "image": "tester:latest",
            "cap_add": ["NET_ADMIN"],
            "entrypoint": ["/bin/sh", "-ec",
                "/share/tc_setup.sh scn_000 16.0mbit ; /share/tc_setup.sh scn_001 16.0mbit"],
            "depends_on": ["scion_br1-ff00_0_111-1", "scion_br1-ff00_0_111-2"],
            "network_mode": "host",
        }
        with open(scion_dc, "w") as file:
            yaml.dump(dc, file)

    def _docker_compose(self, *args) -> str:
        return cmd.docker_compose("-f", self.test_state.artifacts / "gen" / "scion-dc.yml",
                                  "-p", "scion", *args)

    def _refresh_paths(self):
        self._docker_compose("exec", "-T", "tester_1-ff00_0_110", "ping", "-c", "2",
                             "172.20.0.39")
        self._docker_compose("exec", "-T", "tester_1-ff00_0_111", "ping", "-c", "2",
                             "172.20.0.23")
        self._docker_compose("exec", "-T", "tester_1-ff00_0_110", "./bin/scion", "sp",
                             "1-ff00:0:111", "--sciond", "172.20.0.21:30255",
                             "--timeout", "5s", "--refresh", "--local", "172.20.0.20")
        self._docker_compose("exec", "-T", "tester_1-ff00_0_111", "./bin/scion", "sp",
                             "1-ff00:0:110", "--sciond", "172.20.0.37:30255",
                             "--timeout", "5s", "--refresh", "--local", "172.20.0.36")

    def _set_path_count(self, path_count):
        # Change the gateway config.
        config_name = self.test_state.artifacts / "gen" / "ASff00_0_111" / "sig.json"
        with open(config_name, "r") as f:
            t = json.load(f)
        t["ASes"]["1-ff00:0:110"]["PathCount"] = path_count
        with open(config_name, "w") as f:
            json.dump(t, f, indent=2)
        # Reload the config.
        self._docker_compose("kill", "-s", "SIGHUP", "scion_sig_1-ff00_0_111")
        # Give gateway some time to start using the new path count.
        time.sleep(2)

    def _transfer(self, filename, size):
        print("transferring a file (%d MB)" % size)
        # Create a large file.
        self._docker_compose("exec", "-T", "tester_1-ff00_0_111",
                             "fallocate", "-l", "%dM" % size, filename)
        start_time = time.time()
        # Copy it, via ports 40000-40020, to the other AS.
        self._docker_compose("exec", "-T", "tester_1-ff00_0_111",
                             "bbcp", "-s",  "20", "-Z", "40000:40020",
                             "localhost:/share/%s" % filename, "172.20.0.23:/share")
        elapsed = time.time() - start_time
        throughput = float(size * 1024 * 1024 * 8) / 1000000 / elapsed
        print("transfer finished")
        print("time elapsed: %f seconds" % elapsed)
        print("throughput: %f mbps" % throughput)

    def _setup(self):
        print("setting up the infrastructure")

        # First load the images
        cmd.docker("image", "load", "-i", "./demo/file_transfer/containers.tar")

        # Start the topology
        self._docker_compose("up", "-d")

        # Initialize SSH in tester containers (needed by bbcp)
        self._docker_compose("exec", "-T", "tester_1-ff00_0_110", "/bin/bash",
                             "/share/ssh_setup.sh")
        self._docker_compose("exec", "-T", "tester_1-ff00_0_111", "/bin/bash",
                             "/share/ssh_setup.sh")

        # Wait till everything starts working.
        print("waiting")
        time.sleep(30)
        self._refresh_paths()

        print("setup done")

    def _run(self):
        print("--------------------")
        print("using one path")
        self._set_path_count(1)
        self._transfer("foo1.txt", 20)
        print("--------------------")
        print("using two paths")
        self._set_path_count(2)
        self._transfer("foo2.txt", 20)

    def _teardown(self):
        logs = self._docker_compose("logs")
        with open(self.test_state.artifacts / "logs" / "docker-compose.log", "w") as f:
            f.write(logs)
        self._docker_compose("down", "-v")


@Test.subcommand("setup")
class TestSetup(Test):

    def main(self):
        self._setup()


@Test.subcommand("run")
class TestRun(Test):

    def main(self):
        self._run()


@Test.subcommand("teardown")
class TestTeardown(Test):

    def main(self):
        self._teardown()


if __name__ == "__main__":
    log.init_log()
    Test.test_state = base.TestState(scion.SCIONDocker(), tools.DC())
    Test.run()
