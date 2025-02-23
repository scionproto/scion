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

        # Modify test topology configuration by adding a separate NAT'ed docker network (192.168.123.0/24).
        # A new docker container is added which acts as a NAT between the new network and AS1-ff00:0:111 (172.20.0.24/29).
        # The tester container of AS1-ff00:0:111 is moved inside the separate network, along with the accompanying
        # daemon and dispatcher.
        with open (self.artifacts / "gen/scion-dc.yml", "r") as file:
            scion_dc = yaml.safe_load(file)

            # Create new docker network
            scion_dc["networks"]["local_001"] = {
                "driver": "bridge",
                "driver_opts": {"com.docker.network.bridge.name": "local_001"},
                "ipam": {"config": [{"subnet": "192.168.123.0/24"}]}
            }

            # Move tester dispatcher to new network
            scion_dc["services"]["disp_tester_1-ff00_0_111"]["networks"] = {"local_001": {"ipv4_address": "192.168.123.4"}}

            # Move tester daemon to new network & add default route to send packets to NAT (192.168.123.2)
            scion_dc["services"]["sd1-ff00_0_111"]["entrypoint"] = []
            scion_dc["services"]["sd1-ff00_0_111"]["command"] = 'sh -c "ip route del default && ip route add default via 192.168.123.2 && /app/daemon --config /etc/scion/sd.toml && tail -f /dev/null"'
            scion_dc["services"]["sd1-ff00_0_111"]["depends_on"].append("nat_1-ff00_0_111")
            scion_dc["services"]["sd1-ff00_0_111"]["cap_add"] = ["NET_ADMIN"]
            scion_dc["services"]["sd1-ff00_0_111"]["networks"] = {"local_001": {"ipv4_address": "192.168.123.3"}}
            scion_dc["services"]["sd1-ff00_0_111"].pop("user")

            # Move tester container to new network
            scion_dc["services"]["tester_1-ff00_0_110"]["environment"]["SCION_DAEMON_ADDRESS"] = "172.20.0.21:30255"
            scion_dc["services"]["tester_1-ff00_0_111"].pop("entrypoint")
            scion_dc["services"]["tester_1-ff00_0_111"]["command"] = 'sh -c "ip route del default && ip route add default via 192.168.123.2 && tail -f /dev/null"'
            scion_dc["services"]["tester_1-ff00_0_111"]["environment"] = {
                "SCION_DAEMON": "192.168.123.3:30255",
                "SCION_DAEMON_ADDRESS": "192.168.123.3:30255",
                "SCION_LOCAL_ADDR": "192.168.123.4"
            }

            # Create new docker container that acts as a NAT.
            # We use iptables for the NAT (https://www.man7.org/linux/man-pages/man8/iptables.8.html)
            # iptables command breakdown:
            # -t nat                 specifies that the rule applies to the NAT table
            # -A POSTROUTING         appends the rule to the POSTROUTING chain, which is used to modify packets after routing decision and prior to leaving the network interface
            # -s 192.168.123.0/24    specifies the source address range
            # -p tcp/udp             specifies the protocol the rule applies to
            # -o eth1                specifies that the rule applies to packets leaving eth1
            # -j MASQUERADE          dynamically replace source IP of outgoing packets with the IP of eth1
            # --random               uses random source ports
            # --to-ports 31000-32767 specifies to use only ports from the dispatched port range
            # see https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html for more information
            scion_dc["services"]["nat_1-ff00_0_111"] = {
                "command": 'sh -c "apt update && apt install -y iptables && iptables -t nat -A POSTROUTING -s 192.168.123.0/24 -p tcp -o eth1 -j MASQUERADE && iptables -t nat -A POSTROUTING -s 192.168.123.0/24 -p udp -o eth1 -j MASQUERADE --random --to-ports 31000-32767 && tail -f /dev/null"',
                "image": "scion/tester:latest",
                "networks": {
                    "scn_002": {"ipv4_address": "172.20.0.28"},
                    "local_001": {"ipv4_address": "192.168.123.2"},
                },
                "cap_add": ["NET_ADMIN"]
            }
        with open (self.artifacts / "gen/scion-dc.yml", "w") as file:
            yaml.dump(scion_dc, file)

        # More configuration changes to reflect new network topology
        with open (self.artifacts / "gen/networks.conf", "r") as file:
            filecontent = file.read()

        filecontent = filecontent.replace("sd1-ff00_0_111", "nat-ff00_0_111")
        filecontent = filecontent.replace("tester_1-ff00_0_111 = 172.20.0.29", "[192.168.123.0/24]\nnat-ff00_0_111 = 192.168.123.2\nsd1-ff00_0_111 = 192.168.123.3\ntester_1-ff00_0_111 = 192.168.123.4")

        with open (self.artifacts / "gen/networks.conf", "w") as file:
            file.write(filecontent)

        with open (self.artifacts / "gen/sciond_addresses.json", "r") as file:
            filecontent = file.read()

        filecontent = filecontent.replace("172.20.0.28", "192.168.123.4")

        with open (self.artifacts / "gen/sciond_addresses.json", "w") as file:
            file.write(filecontent)

        with open (self.artifacts / "gen/ASff00_0_111/sd.toml", "r") as file:
            filecontent = file.read()

        filecontent = filecontent.replace("172.20.0.28", "192.168.123.3")

        with open (self.artifacts / "gen/ASff00_0_111/sd.toml", "w") as file:
            file.write(filecontent)

    def _run(self):
        time.sleep(20) # wait for everything to start up

        # copy test executables to test container
        stun_client = local["realpath"](self.get_executable("test-client-demo").executable).strip()
        stun_server = local["realpath"](self.get_executable("test-server-demo").executable).strip()
        self.dc("cp", stun_server, "tester_1-ff00_0_110" + ":/bin/")
        self.dc("cp", stun_client, "tester_1-ff00_0_111" + ":/bin/")

        # run tests (located in test-client/main.go and test-server/main.go)
        self.dc.execute_detached("tester_1-ff00_0_110", "sh", "-c", "test-server-demo -local 1-ff00:0:110,172.20.0.22:31000")
        time.sleep(3)
        result = self.dc.execute("tester_1-ff00_0_111", "sh", "-c", 'test-client-demo -daemon 192.168.123.3:30255 -local 1-ff00:0:111,192.168.123.4:31000 -remote 1-ff00:0:110,172.20.0.22:31000 -data "abc"')
        print(result)

if __name__ == "__main__":
    base.main(Test)
