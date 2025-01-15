#!/usr/bin/env python3

# Copyright 2024 ETH Zurich
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

from acceptance.common import base, scion
import time
import yaml
from plumbum import cmd
from plumbum import local


class Test(base.TestTopogen):
    def setup_prepare(self):
        super().setup_prepare()
        cmd.cp(local.cwd / "demo/stun/scion-dc_nat.yml", self.artifacts / "gen/scion-dc.yml")
        cmd.cp(local.cwd / "demo/stun/sciond_addresses_nat.json", self.artifacts / "gen/sciond_addresses.json")
        cmd.cp(local.cwd / "demo/stun/networks_nat.conf", self.artifacts / "gen/networks.conf")
        cmd.cp(local.cwd / "demo/stun/sd_nat.toml", self.artifacts / "gen/ASff00_0_111/sd.toml")

    def _run(self):
        time.sleep(20) # wait for everything to start up

        stun_client = local["realpath"](self.get_executable("test-client-demo").executable).strip()
        stun_server = local["realpath"](self.get_executable("test-server-demo").executable).strip()
        self.dc("cp", stun_server, "tester_1-ff00_0_110" + ":/bin/")
        self.dc("cp", stun_client, "tester_1-ff00_0_111" + ":/bin/")

        self.dc.execute_detached("tester_1-ff00_0_110", "sh", "-c", "test-server-demo -local 1-ff00:0:110,172.20.0.22:31000")
        time.sleep(5)
        result = self.dc.execute("tester_1-ff00_0_111", "sh", "-c", 'test-client-demo -daemon 192.168.123.3:30255 -local 1-ff00:0:111,192.168.123.4:31000 -remote 1-ff00:0:110,172.20.0.22:31000 -data "abc"')
        print(result)

if __name__ == "__main__":
    base.main(Test)
