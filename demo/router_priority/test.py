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
# from plumbum import local


# deleteme remove once we run this as a test.
def selfdc(*args) -> str:
    cmd = ["docker","compose", "-f", "gen/scion-dc.yml"] + list(args)
    print(f"running {cmd}")

    try:
        output = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"docker compose failed: {e.stderr}") from e
    return output.stdout.strip()


def get_service_info(service: str) -> Dict:
    output = selfdc("ps", "--format", "json")
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


def get_interface_indices(service_name:str) -> List[int]:
    """
    Returns the equivalent of running:
    sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' container ) -n ip link

    :param container: Container name, e.g. scion-br1-ff00_0_111-1-1
    """
    # Step 1: get PID: info["PID"].
    service_info = get_service_info(service_name)
    # Step 2: nsenter + ip link
    proc = subprocess.run(
        ["sudo", "nsenter", "-t", service_info["PID"], "-n", "ip", "link"],
        text=True,
        capture_output=True,
        check=True
    )
    # Step 3: parse output: the output contains 2 lines per interface, like this:
    # 2: eth0@if751: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default
    #     link/ether 0e:40:6f:f3:6e:d7 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    # We only need the first line, and only the second "field" of that line.
    iface_re = re.compile(r'^\s*\d+:\s+([^:]+):')
    interfaces = [
        m.group(1)
        for line in proc.stdout.splitlines()
        if (m := iface_re.match(line))
    ]
    # Step 4: strip eth0@if out of the name of the interface:
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
    # bridges_re = re.compile(r"^\s*(\d+):\s+([^\s:]+):.*?(?:\bmaster\s+(\S+))?")
    # bridges_re = re.compile(r"^\s*(\d+):\s+([^\s:]+):.*master\s+(\S+)")
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
    # try to reset the qdisc of the device.
    try:
        proc = subprocess.run(
            ["sudo", "tc", "qdisc", "del", "dev", bridge, "root"],
            check=True
        )
    except subprocess.CalledProcessError as e:
        # ignore failure (fails if not already set).
        pass

    # set qdisc of the device to 1Mbps:
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
            # each sample has .value and .labels
            metric["total"] += sample.value
            # sample.labels is a dictionary like {'interface': '41', 'isd_as': '1-ff00:0:111'}
            for label, label_value in sample.labels.items():
                if label in metric:
                    metric[label][label_value] += sample.value
    return metrics





def aggregate_metrics(full_text:str, metric_label:str) -> Tuple[int, Dict[str, int]]:
    """returns the total and per interface aggregated (sum) metrics"""
    total = 0
    by_interface = defaultdict(int)

    for family in text_string_to_metric_families(full_text):
        if family.name != metric_label:
            continue

        for sample in family.samples:
            labels = sample.labels
            value = sample.value

            total += value
            by_interface[labels["interface"]] += value

    return total, dict(by_interface)


def measure_metrics_rate(url: str, sample_seconds:float, labels: List[str]) -> List[
        Tuple[float, Dict[str, float]]]:
    # Get initial values:
    text = requests.get(url).text
    t0 = time.monotonic()
    totals = [] # one per label
    by_ifs = [] # one per label
    for label in labels:
        last_total, last_by_if = aggregate_metrics(text, label)
        totals.append(last_total)
        by_ifs.append(last_by_if)

    # Sleep.
    time.sleep(sample_seconds)

    # Get new values:
    text = requests.get(url).text
    duration = time.monotonic() - t0
    for i in range(len(labels)):
        label = labels[i]
        total, by_if = aggregate_metrics(text, label)
        # Relative to last measurement:
        rel_total = total - totals[i]
        rel_by_if = {k:by_if[k] - v for k,v in by_ifs[i].items()}

        # Compute average.
        avg_total = rel_total / duration
        avg_by_if = {k:v / duration for k, v in rel_by_if.items()}

        # Update lists:
        totals[i] = avg_total
        by_ifs[i] = avg_by_if
    return totals, by_ifs


# def measure_metrics():
#     text = requests.get("http://172.20.0.26:30442/metrics").text
#     labels = [
#         "router_bfd_sent_packets",
#         "router_bfd_state_changes",
#         "router_dropped_pkts",
#         "router_output_pkts",
#         "router_output_bytes",
#     ]
#     for label in labels:
#         total, by_if = aggregate_metrics(text, label)
#         print(f"{label} TOTAL :", total)
#         print(f"{label} BY IF:", by_if)

#     totals, by_ifs = measure_metrics_rate(
#         "http://172.20.0.26:30442/metrics",
#         2.0,
#         labels,
#     )
#     print("------- RATES ---------")
#     for i in range(len(labels)):
#         print(f"{labels[i]} total = {totals[i]}, by_if = {by_ifs[i]}")










def run_scion_ping(src_container:str, dst_endpoint:str, count:int, size:int, interval:str) -> float:
    """Returns the loss rate 0..100"""
    cmd = ["scion","ping","--format", "yaml",
           "-c", str(count), "-s", str(size), "--interval", str(interval), dst_endpoint]
    lines = selfdc("exec", src_container, *cmd)
    ping = yaml.safe_load(lines)
    stats = ping["statistics"]
    print(f"sent: {stats["sent"]}")
    print(f"recv: {stats["received"]}")
    print(f"loss: {stats["packet_loss"]}")
    return float(stats["packet_loss"])


def run_heavy_scion_ping(src_container: str, dst_endpoint:str) -> float:
    # docker compose -f gen/scion-dc.yml exec tester_1-ff00_0_111 scion ping --format yaml -c 3000 -s 2000 --interval 1ms 1-ff00:0:112,fd00:f00d:cafe::7f00:15
    loss = run_scion_ping(src_container,dst_endpoint,count=3000,size=2000, interval="1ms")
    return loss


def increase_load(src_service:str, dst_endpoint: str, duration: str) -> None:
    # go build -o sender ./demo/router_priority/sender/ &&   sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' scion-tester_1-ff00_0_111-1 ) -n ./sender -daemon 172.20.0.28:30255 -local 172.20.0.29:0 -remote 1-ff00:0:112,[fd00:f00d:cafe::7f00:15]:12345 -duration 60s
    # deleteme run directly in the container after copying the binary with dc cp
    service_info = get_service_info(src_service)
    cmd = ["sudo", "nsenter", "-t", service_info["PID"], "-n",
           "./sender", "-daemon", "172.20.0.28:30255", "-local", "172.20.0.29:0",
           "-remote", dst_endpoint,
           "-duration", duration ]
    try:
        subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"docker compose failed: {e.stderr}") from e



class Test(base.TestTopogen):
    def setup_prepare(self):
        super().setup_prepare()

        # We need to set up bandwidth limits to the interface of BR-1 @ 1-ff00:0:111,
        # to ensure that we will see packet drops when running a high bandwidth test with
        # scion ping. We should see no losses on priority traffic, e.g. BFD packets.

        # From the host, we obtain all the interfaces of the BR-1 @ 111 container:

        # sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' scion-br1-ff00_0_111-1-1 ) -n ip link
        # ip link | grep veth


        # with (open(self.artifacts / "gen/scion-dc.yml", "r") as file):
        #     scion_dc = yaml.safe_load(file)

        # with open(self.artifacts / "gen/scion-dc.yml", "w") as file:
        #     yaml.dump(scion_dc, file)

    def _run(self):
        print("deleteme running priority test")
        print(f"interfaces: {get_interface_indices("scion-br1-ff00_0_111-1-1")}")


def deleteme():
    print("deleteme running priority test")
    # sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' scion-br1-ff00_0_111-1-1 ) -n ip link
    # List interfaces of the BR-111 container.
    indices = get_interface_indices("br1-ff00_0_111-1")
    # ip -o link show
    # Get the network interface for BR-111 -> BR-110 (network is scn_000).
    bridge = get_host_bridge_interface(indices, "scn_000")
    print(f"bridge is: {bridge}")
    # sudo tc qdisc add dev veth31e7685@if3 root tbf rate 1mbit burst 32kbit latency 400ms
    # Limit the BR-111 -> BR-110 interface to 1Mbps.
    set_tc_limits(bridge, rate="1mbit", burst="32kbit", latency="400ms")

    # # curl  http://172.20.0.26:30442/metrics | grep bfd_sent
    # measure_metrics()
    # # # Test: measure rates continuously:
    # # labels = [
    # #     "router_bfd_sent_packets",
    # #     "router_dropped_pkts",
    # #     "router_output_pkts",
    # #     "router_output_bytes",
    # # ]
    # # while True:
    # #     t0 = time.monotonic()
    # #     totals, by_ifs = measure_metrics_rate(
    # #         "http://172.20.0.26:30442/metrics",
    # #         1.0,
    # #         labels,
    # #     )
    # #     t1 = time.monotonic()
    # #     print(f"------- RATES --------- (after {(t1-t0):.3f} seconds)")
    # #     for i in range(len(labels)):
    # #         print(f"{labels[i]} total = {totals[i]}, by_if = {by_ifs[i]}")


    # Increment bandwidth load significantly:

    # # ---------------------
    # loss = run_heavy_scion_ping("tester_1-ff00_0_111", "1-ff00:0:112,fd00:f00d:cafe::7f00:15")
    # print(f"heavy traffic scion ping has a loss of {loss}")
    # # Wait a bit and check that all works again
    # time.sleep(1)
    # loss = run_scion_ping("tester_1-ff00_0_111", "1-ff00:0:112,fd00:f00d:cafe::7f00:15",
    #                count=3,size=1000,interval="1s")
    # print(f"regular scion ping has a loss of {loss}")
    # # --------------------------
    #
    # go run ./demo/router_priority/sender/ -daemon 127.0.0.19:30255 -remote 1-ff00:0:110,127.0.0.1:12345
    # go run ./demo/router_priority/sender/ -daemon 172.20.0.28:30255 -local 172.20.0.29:0 -remote 1-ff00:0:112,[fd00:f00d:cafe::7f00:15]:12345

    # Build sender binary:
    # go build -o sender ./demo/router_priority/sender/
    # Run sender but in the tester-111 network namespace:
    # sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' scion-tester_1-ff00_0_111-1 ) -n ./sender -daemon 172.20.0.28:30255 -local 172.20.0.29:0 -remote 1-ff00:0:112,[fd00:f00d:cafe::7f00:15]:12345

    # go build -o sender ./demo/router_priority/sender/ &&   sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' scion-tester_1-ff00_0_111-1 ) -n ./sender -daemon 172.20.0.28:30255 -local 172.20.0.29:0 -remote 1-ff00:0:112,[fd00:f00d:cafe::7f00:15]:12345 -duration 60s

    # Measure ping loss before loading the BR:
    loss = run_scion_ping("tester_1-ff00_0_111", "1-ff00:0:112,fd00:f00d:cafe::7f00:15",
                          count=3,size=1000,interval="1s")
    print(f"initial ping loss is {loss}")
    if loss > 90.0:
        raise RuntimeError(f"The initial ping command has too high a loss ratio: {loss}")
    # Measure BR-111 before increasing the load:
    metrics_before = measure_br("http://172.20.0.26:30442/metrics")

    # Increase the load for 1 minute by blasting the destination with SCION UDP packets:
    increase_load("tester_1-ff00_0_111", "1-ff00:0:112,[fd00:f00d:cafe::7f00:15]:12345", "60s")

    # Ping again.
    loss = run_scion_ping("tester_1-ff00_0_111", "1-ff00:0:112,fd00:f00d:cafe::7f00:15",
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
    print(f"router metrics follow. Before:\n{metrics_before}\n"
          f"After: {metrics_after}")
    return
    # scion ping -s 4000 --interval 1ms 1-ff00:0:112,fd00:f00d:cafe::7f00:15
    # scion ping -s 4000 1-ff00:0:112,fd00:f00d:cafe::7f00:15

    # # This works:
    # scion ping -s 1000 --interval 100ms 1-ff00:0:110,172.20.0.22







if __name__ == "__main__":
    # base.main(Test)
    deleteme()
    # sudo tc qdisc add dev vethXYZ root tbf rate 1mbit burst 32kbit latency 400ms


# We need the following pip extra packages:
# - prometheus-client
# - requests


# docker compose -f gen/scion-dc.yml restart br1-ff00_0_111-1
# OR
# scion.sh stop ; make && make docker-images && ./scion.sh start && sleep 10 && ./bin/end2end_integration -d

# ip -o link show | grep scn_000  # BR111->BR110
# sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' scion-br1-ff00_0_111-1-1 ) -n ip address
# sudo tc qdisc add dev vethfb8dc0d root tbf rate 1mbit burst 32kbit latency 400ms


# docker compose -f gen/scion-dc.yml exec -it tester_1-ff00_0_111 bash

# sudo tcpdump -i any 'udp' -w sender.pcap ; sudo chown juan:juan sender.pcap


# docker compose -f gen/scion-dc.yml logs br1-ff00_0_111-1 -f
# curl -s http://172.20.0.26:30442/metrics | grep bfd_sent
# curl -s http://172.20.0.26:30442/metrics | grep bfd
# curl -s http://172.20.0.26:30442/metrics | grep drop
# curl -s http://172.20.0.26:30442/metrics  | grep processed_pkts

# Blast the router with SCION UDP:
# go build -o sender ./demo/router_priority/sender/ &&   sudo nsenter -t $(docker inspect -f '{{.State.Pid}}' scion-tester_1-ff00_0_111-1 ) -n ./sender -daemon 172.20.0.28:30255 -local 172.20.0.29:0 -remote 1-ff00:0:112,[fd00:f00d:cafe::7f00:15]:12345 -duration 60s


# Check that still works after the blast:
# docker compose -f gen/scion-dc.yml exec tester_1-ff00_0_111 scion ping -c 3 1-ff00:0:112,fd00:f00d:cafe::7f00:15


"""
172.20.0.26 BR-1    @ 111
172.20.0.27 disp CS @ 111
172.20.0.28 daemon  @ 111
172.20.0.29 tester  @ 111

ip.addr == 172.20.0.0/16 and ip.src==172.20.0.3
udp && scion && scion.next_hdr == 202 && scmp.type
udp && scion && scion.src_host == "172.20.0.29" && scion.payload_len == 1108 && scion_udp.dst_port == 12345

"""
