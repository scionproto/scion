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
import time

import plumbum

from acceptance.common import base
from acceptance.common import tools
from acceptance.common import scion


class Test(base.TestBase):
    """
    Tests that reloading the traffic json configuration correctly works in the
    Gateway.
    """
    gateway_acceptance = plumbum.cli.SwitchAttr("gateway_acceptance", str,
                                                default="./bin/sig_ping_acceptance",
                                                help="The gateway ping acceptance binary" +
                                                " (default: ./bin/sig_ping_acceptance)")

    def main(self):
        if not self.nested_command:
            try:
                self.setup()
                time.sleep(20)
                self._run()
            finally:
                self.teardown()

    def _run(self):
        ping_test = plumbum.local[self.gateway_acceptance]

        src_ia = "1-ff00:0:111"
        dst_ia = "1-ff00:0:112"

        print("Running ping test")
        print(ping_test("-d", "-outDir", self.test_state.artifacts, "-src", src_ia, "-dst", dst_ia))
        print("Ping done")

        print("Remove 1-ff00:0:112 from remotes")
        remote_cfg = self._pop_remote(dst_ia)
        print("Running ping test")
        print(ping_test("-d", "-outDir", self.test_state.artifacts, "-src", src_ia, "-dst", dst_ia,
                        "-fail"))

        print("Restore remote")
        self._put_remote(dst_ia, remote_cfg)
        print("Running ping test")
        print(ping_test("-d", "-outDir", self.test_state.artifacts, "-src", src_ia, "-dst", dst_ia))
        print("Ping done")

    def _pop_remote(self, dst_ia: str):
        with open(self.test_state.artifacts / "gen" / "ASff00_0_111" / "sig.json", "r+") as f:
            cfg = json.load(f)
            res = cfg["ASes"].pop(dst_ia, None)
            f.seek(0)
            json.dump(cfg, f, indent=2)
            f.truncate()
        self.send_signal("scion_sig_1-ff00_0_111", "SIGHUP")
        time.sleep(4)
        return res

    def _put_remote(self, dst_ia: str, remote_cfg):
        with open(self.test_state.artifacts / "gen" / "ASff00_0_111" / "sig.json", "r+") as f:
            cfg = json.load(f)
            res = cfg["ASes"][dst_ia] = remote_cfg
            f.seek(0)
            json.dump(cfg, f, indent=2)
            f.truncate()
        self.send_signal("scion_sig_1-ff00_0_111", "SIGHUP")
        time.sleep(4)
        return res


if __name__ == "__main__":
    base.register_commands(Test)
    Test.test_state = base.TestState(scion.SCIONDocker(), tools.DC())
    Test.run()
