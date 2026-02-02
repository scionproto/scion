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

from acceptance.common import base
from collections import defaultdict
from prometheus_client.parser import text_string_to_metric_families
from typing import Iterable, Dict, List, Tuple
import json
import os
import re
import requests
import subprocess
import sys
import time
import yaml
from plumbum import local


def measure_br(url: str):
    metrics = {
        "router_bfd_state_changes":{
            "total": 0,
        },
        "router_bfd_sent_packets":{
            "total": 0,
            "interface": defaultdict(int),
        },
        "router_bfd_received_packets":{
            "total": 0,
            "interface": defaultdict(int),
        },
        "router_dropped_pkts":{
            "total": 0,
            "interface": defaultdict(int),
            "reason": defaultdict(int),
        },
        "router_output_pkts":{
            "total": 0,
            "interface": defaultdict(int),
        },
    }
    text = requests.get(url).text
    for family in text_string_to_metric_families(text):
        if not family.name in metrics:
            continue
        metric = metrics[family.name]
        for sample in family.samples:
            # Each sample has .value and .labels
            metric["total"] += sample.value
            # sample.labels is a dictionary like {'interface': '41', 'isd_as': '1-ff00:0:111'}
            for label, label_value in sample.labels.items():
                if label in metric:
                    metric[label][label_value] += sample.value
    return metrics


class Test(base.TestTopogen):
    def setup_prepare(self):
        super().setup_prepare()
        # Add throttling to the BR-111 <-> BR-110 link.
        scion_dc = self.artifacts / "gen/scion-dc.yml"
        with open(scion_dc, "r") as file:
            dc = yaml.load(file, Loader=yaml.FullLoader)
        dc["services"]["tc_setup"] = {
            "image": "scion/tester:latest",
            "cap_add": ["NET_ADMIN"],
            "volumes": [{
                "type": "bind",
                "source": os.path.realpath("demo/router_priority/tc_setup.sh"),
                "target": "/share/tc_setup.sh",
            }],
            "entrypoint": ["/bin/bash", "-exc",
                           "ls -l /share; /share/tc_setup.sh scn_000 512kbit; "
                           "echo TC limits applied to scn_000"],
            "depends_on": ["br1-ff00_0_110-1", "br1-ff00_0_111-1"],
            "network_mode": "host",
        }
        with open(scion_dc, "w") as file:
            yaml.dump(dc, file)

    def _run(self):
        print("-------------------- running router_priority test")
        self.await_connectivity()
        # Copy the sender binary to the tester-111 container (used to apply load).
        sender_bin = local["realpath"](self.get_executable("sender").executable).strip()
        self.dc("cp", sender_bin, "tester_1-ff00_0_111" + ":/bin/")

        # Measure ping loss before loading the BR:
        loss = self._run_scion_ping("tester_1-ff00_0_111", "1-ff00:0:112,fd00:f00d:cafe::7f00:15",
                                    count=3,size=1000,interval="1s")
        print(f"initial ping loss is {loss}")
        if loss > 90.0:
            raise RuntimeError(f"The initial ping command has too high a loss ratio: {loss}")
        # Measure BR-111 before increasing the load:
        metrics_before = measure_br("http://172.20.0.26:30442/metrics")

        # Increase the load for 1 minute by blasting the destination with SCION UDP packets:
        # result = self.dc.execute("tester_1-ff00_0_111",
        result = self.dc("exec", "tester_1-ff00_0_111", "bash", "-c",
            "sender -daemon 172.20.0.28:30255 -local 172.20.0.29:0 -duration 60s " +
            "-remote 1-ff00:0:112,[fd00:f00d:cafe::7f00:15]:12345",
        )
        print(result)

        # Ping again.
        loss = self._run_scion_ping("tester_1-ff00_0_111", "1-ff00:0:112,fd00:f00d:cafe::7f00:15",
                                    count=3,size=1000,interval="1s")
        print(f"final ping loss is {loss}")
        if loss > 90.0:
            print(f"The initial ping command has too high a loss ratio: {loss}")
            sys.exit(1)
        # Measure BR-111 after the load increase:
        metrics_after = measure_br("http://172.20.0.26:30442/metrics")
        bfd_changes = metrics_after["router_bfd_state_changes"]["total"] -\
            metrics_before["router_bfd_state_changes"]["total"]
        print(f"BFD state changes: {bfd_changes}")
        if bfd_changes != 0:
            print(f"BFD state should have not changed, but had {bfd_changes} changes.")
            sys.exit(1)
        busy_fwd = metrics_after["router_dropped_pkts"]["reason"]["busy_forwarder"] -\
            metrics_before["router_dropped_pkts"]["reason"]["busy_forwarder"]
        if busy_fwd == 0:
            print(f"Insufficient load: no packet drop occurred.")
            sys.exit(1)
        print(f"router metrics follow.\n"
            f"Before:\n-----8<-----\n{metrics_before}\n-----8<-----\n"
            f"After: \n-----8<-----\n{metrics_after}\n-----8<-----")
        print("Success.")
        print(f"-------------------- finished router_priority test")

    def _run_scion_ping(self, src_container:str, dst_endpoint:str,
                       count:int, size:int, interval:str) -> float:
        """Returns the loss rate 0..100"""
        cmd = ["scion","ping","--format", "yaml",
            "-c", str(count), "-s", str(size), "--interval", str(interval), dst_endpoint]
        lines = self.dc("exec", src_container, *cmd)
        ping = yaml.safe_load(lines)
        stats = ping["statistics"]
        return float(stats["packet_loss"])


if __name__ == "__main__":
    base.main(Test)
