#!/usr/bin/env python3

# Copyright 2022 ETH Zurich
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

import logging
import os
import random
import re
import time
import yaml

from plumbum import local
from plumbum.path import LocalPath

from acceptance.common import base, scion
from tools.topology.scion_addr import ISD_AS

logger = logging.getLogger(__name__)


class Test(base.TestTopogen):
    def _init_as_list(self):
        # load list of ASes (generated by topogen scripts)
        as_list = self.artifacts / "gen/as_list.yml"
        self.isd_ases = scion.ASList.load(as_list).all

        # pick two "random" ASes (can be the same) for our "server" and "client" side key derivation
        # demonstration.
        # Note: fix random seed between invocations (prepare and run stages stages can be run
        # separately)
        random.seed(os.path.getctime(as_list))
        self.server_isd_as, self.client_isd_as = random.choices(self.isd_ases, k=2)

    def setup_prepare(self):
        super().setup_prepare()

        self._init_as_list()

        # Enable DRKey in all CSes and SDs
        for isd_as in self.isd_ases:
            conf_dir = self._conf_dir(isd_as)
            scion.update_toml({
                "drkey": {
                    "level1_db": {
                        "connection": "/share/cache/cs%s-1.drkey_level1.db" % isd_as.file_fmt(),
                    },
                    "secret_value_db": {
                        "connection": "/share/cache/cs%s-1.secret_value.db" % isd_as.file_fmt()
                    }
                }
            }, conf_dir // "cs*-1.toml")

            scion.update_toml({
                "drkey_level2_db": {
                    "connection": "/share/cache/sd%s.drkey_level2.db" % isd_as.file_fmt()
                }
            }, [conf_dir / "sd.toml"])

        # Enable delegation for demo "server", i.e. allow server to
        # access the base secret value from which keys can be derived locally.
        server_ip = self._server_ip(self.server_isd_as)
        server_cs_config = self._conf_dir(self.server_isd_as) // "cs*-1.toml"
        scion.update_toml({"drkey.delegation.scmp": [server_ip]}, server_cs_config)

    def _run(self):
        time.sleep(10)  # wait until CSes are all up and running

        self._init_as_list()

        # install demo binary in tester containers:
        drkey_demo = local["realpath"](self.get_executable("drkey-demo").executable).strip()
        testers = ["tester_%s" % ia.file_fmt() for ia in {self.server_isd_as, self.client_isd_as}]
        for tester in testers:
            local["docker"]("cp", drkey_demo, tester + ":/bin/")

        # Define DRKey protocol identifiers and derivation typ for test
        for test in [
            {"protocol": "1", "fetch_sv": "--fetch-sv"},  # SCMP based on protocol specific SV
            {"protocol": "1", "fetch_sv": ""},            # SCMP based on generic key derivation
            {"protocol": "7", "fetch_sv": ""},            # Generic "niche" protocol
        ]:
            # Determine server and client addresses for test.
            # Because communication to the control services does not happen
            # directly from the respective end hosts but via daemon processes on
            # both sides, the IPs of the corresponding daemon hosts are used for
            # this purpose. See also function _endhost_ip for more details.
            server_ip = self._endhost_ip(self.server_isd_as)
            client_ip = self._endhost_ip(self.client_isd_as)
            server_addr = "%s,%s" % (self.server_isd_as, server_ip)
            client_addr = "%s,%s" % (self.client_isd_as, client_ip)

            # Demonstrate deriving key (fast) on server side
            rs = self.dc.execute("tester_%s" % self.server_isd_as.file_fmt(),
                                 "drkey-demo", "--server",
                                 "--protocol", test["protocol"], test["fetch_sv"],
                                 "--server-addr", server_addr, "--client-addr", client_addr)
            print(rs)

            # Demonstrate obtaining key (slow) on client side
            rc = self.dc.execute("tester_%s" % self.client_isd_as.file_fmt(),
                                 "drkey-demo", "--protocol", test["protocol"],
                                 "--server-addr", server_addr, "--client-addr", client_addr)
            print(rc)

            # Extract printed keys from output and verify that the keys match
            key_regex = re.compile(
                r"^(?:Client|Server):\s*host key\s*=\s*([a-f0-9]+)", re.MULTILINE)
            server_key_match = key_regex.search(rs)
            if server_key_match is None:
                raise AssertionError("Key not found in server output")
            server_key = server_key_match.group(1)
            client_key_match = key_regex.search(rc)
            if client_key_match is None:
                raise AssertionError("Key not found in client output")
            client_key = client_key_match.group(1)
            if server_key != client_key:
                raise AssertionError("Key derived by server does not match key derived by client!",
                                     server_key, client_key)

    def _server_ip(self, isd_as: ISD_AS) -> str:
        """ Determine the IP used for the "server" in the given ISD-AS """
        return self._container_ip("tester_%s" % isd_as.file_fmt())

    def _client_ip(self, isd_as: ISD_AS) -> str:
        """ Determine the IP used for the "client" in the given ISD-AS """
        # The client's address must be the daemon (as this makes requests to the CS on behalf of the
        # application).
        return self._container_ip("scion_sd%s" % isd_as.file_fmt())

    def _container_ip(self, container: str) -> str:
        """ Determine the IP of the container """
        dc_config = yaml.safe_load(self.dc.compose_file.read())
        networks = dc_config["services"][container]["networks"]
        addresses = next(iter(networks.values()))
        return next(iter(addresses.values()))

    def _conf_dir(self, isd_as: ISD_AS) -> LocalPath:
        """ Returns the path of the configuration directory for the given ISD-AS """
        return self.artifacts / "gen" / ("AS" + isd_as.as_file_fmt())


if __name__ == '__main__':
    base.main(Test)
