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
import re
import requests
import subprocess
import sys
import time
import yaml
from plumbum import local


def get_interface_indices(service_info:Dict) -> List[int]:
    """
    Returns the equivalent of running:
    sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' container ) -n ip link

    :param container: Container name, e.g. scion-br1-ff00_0_111-1-1
    """
    # With nsenter, find the interfaces of the container.
    proc = subprocess.run(
        ["sudo", "nsenter", "-t", service_info["PID"], "-n", "ip", "link"],
        text=True,
        capture_output=True,
        check=True
    )
    # Parse output: the output contains 2 lines per interface, like this: (first line broken at \)
    # 2: eth0@if751: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 \
    # qdisc noqueue state UP mode DEFAULT group default
    #     link/ether 0e:40:6f:f3:6e:d7 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    # We only need the first line, and only the second "field" of that line.
    iface_re = re.compile(r'^\s*\d+:\s+([^:]+):')
    interfaces = [
        m.group(1)
        for line in proc.stdout.splitlines()
        if (m := iface_re.match(line))
    ]
    # Strip eth0@if out of the name of the interface:
    index_re = re.compile(r'^eth\d+@if(\d+)')
    indices = [
        int(m.group(1))
        for iface in interfaces
        if (m:= index_re.match(iface))
    ]
    return indices


def get_host_bridge_interface(indices: Iterable[int], network_name:str) -> str:
    """Given the indices, it returns the first interface that matches the given network."""
    proc = subprocess.run(
        ["ip", "-o", "link", "show"],
        text=True,
        capture_output=True,
        check=True
    )
    lines = proc.stdout.splitlines()
    # Output is like: (lines intentionally broken with "\")
    # 869: scn_000: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode \
    #   DEFAULT group default \    link/ether 62:53:60:c8:e2:e5 brd ff:ff:ff:ff:ff:ff
    # 870: scn_003: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode \
    #   DEFAULT group default \    link/ether c2:b7:65:8b:c1:ef brd ff:ff:ff:ff:ff:ff
    # 871: vethf9d48a7@if2: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue \
    #   master scn_003 state UP mode DEFAULT group default \    link/ether 86:e9:1d:77:c9:1f brd ff:ff:ff:ff:ff:ff link-netnsid 0
    bridges_re = re.compile(r"^\s*(\d+):\s+([^\s@]+)@if\d+.*master\s+(\S+)")
    for line in lines:
        m = bridges_re.match(line)
        if not m:
            continue
        idx = int(m.group(1))
        if not idx in indices:
            continue
        network = m.group(3)
        if network == network_name:
            return m.group(2)
    raise RuntimeError(f"did not find the bridge for {network_name} and indices: {indices}")


def set_tc_limits(bridge:str, rate:str, burst:str, latency:str) -> None:
    # Try to reset the qdisc of the device.
    try:
        subprocess.run(
            ["sudo", "tc", "qdisc", "del", "dev", bridge, "root"],
            check=True,
            capture_output=True,
        )
    except subprocess.CalledProcessError as e:
        # Ignore failure (fails if not already set).
        pass

    # Set qdisc of the device to 1Mbps:
    try:
        subprocess.run(
            ["sudo", "tc", "qdisc", "add", "dev", bridge,
            "root", "tbf", "rate", rate, "burst", burst, "latency", latency],
            text=True,
            capture_output=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(e.stderr)
        raise RuntimeError(f"command tc failed: {e.stderr}") from e


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

    def _run(self):
        print("-------------------- running router_priority test")
        self.await_connectivity()
        # Copy the sender binary to the tester-111 container (used to apply load).
        sender_bin = local["realpath"](self.get_executable("sender").executable).strip()
        self.dc("cp", sender_bin, "tester_1-ff00_0_111" + ":/bin/")

        # Get the BR-111 service information.
        service_info = self._get_service_info("br1-ff00_0_111-1")
        # List interfaces of the BR-111 container.
        indices = get_interface_indices(service_info)
        # Match those interfaces with one of the host interfaces.
        bridge = get_host_bridge_interface(indices, "scn_000")
        print(f"bridge is: {bridge}")
        # Limit the BR-111 -> BR-110 interface to 1Mbps.
        set_tc_limits(bridge, rate="512kbit", burst="32kbit", latency="400ms")
        print(f"tc limits applied to host interface {bridge} (scn_000: BR-110 <-> BR-111)")

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

    def _get_service_info(self, service: str) -> Dict:
        """Returns a dictionary with some information about the container.
        This function additionally sets the PID of the container to the returned information."""
        output = self.dc("ps", "--format", "json")
        # Currently, `docker compose top --format json` does NOT return a valid json string, but a
        # bunch of lines containing valid json strings. Split into lines and treat them separately.
        output = output.splitlines()
        service_dict = None
        for line in output:
            ps_out = json.loads(line)
            if ps_out["Service"] == service:
                service_dict = ps_out
                break
        # If we found the service, get its PID and add it to the dictionary.
        if service_dict is not None:
            try:
                pid = subprocess.check_output(
                    ["docker", "inspect", "-f", "{{.State.Pid}}", service_dict["Name"]],
                    text=True,
                    stderr=subprocess.PIPE,
                ).strip()
            except subprocess.CalledProcessError as e:
                if "No such object" in e.stderr:
                    raise RuntimeError(f"Container '{service_dict["Name"]}' does not exist") from e
                raise RuntimeError("Docker inspect failed") from e
            service_dict["PID"] = pid
        return service_dict

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
