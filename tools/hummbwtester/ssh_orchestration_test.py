import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.hummbwtester import orchestration
from tools.hummbwtester import ssh_orchestration as ssh


class InventoryTest(unittest.TestCase):
    def write_json(self, directory, name, value):
        path = Path(directory) / name
        path.write_text(json.dumps(value))
        return path

    def workload(self):
        return {
            "hummingbird": {"reservation_source": "keys"},
            "server": {"isd_as": "1-ff00:0:112", "host": "fd00::1", "port": 12345,
                       "receive_buffer_size": 4096},
            "hummingbird_clients": [{
                "client_id": "hummingbird-1", "isd_as": "1-ff00:0:111", "host": "fd00::2",
                "port": 0, "bandwidth": "1Mbps", "maxburst": "2Mbps", "duration": "1m",
                "hummingbird_reservation": {"bandwidth": 1, "duration": "1m", "reverse_bandwidth": 0},
            }],
            "best_effort_clients": [{
                "client_id": "best-effort-1", "isd_as": "1-ff00:0:110", "host": "fd00::3",
                "port": 0, "bandwidth": "1Mbps", "maxburst": "2Mbps", "duration": "1m",
            }],
            "router": {"send_buffer_size": 1, "receive_buffer_size": 1, "ingress_batch_size": 1,
                       "processor_queue_size": 1, "egress_batch_size": 1, "egress_queue_size": 1},
            "tc": {"rate": "10mbit", "burst": "50kb", "limit": "256kb"},
        }

    def inventory(self):
        return {
            "hosts": {
                "a": {"ssh": "sciera-rnp", "sciond": "127.0.0.1:30255",
                      "run_dir": "/var/tmp/hummbwtester"},
                "b": {"ssh": "sciera-ufes", "sciond": "127.0.0.1:30255",
                      "run_dir": "/var/tmp/hummbwtester"},
            },
            "placements": {"server": "a", "clients": {"hummingbird-1": "b", "best-effort-1": "a"}},
            "metrics": {"local_port_base": 19090, "routers": [{
                "host": "a", "address": "127.0.0.1:30442", "labels": {"br": "br-1"},
            }]},
            "shaping": [{"host": "a", "device": "eno4.140", "baseline": "noqueue"}],
        }

    def test_inventory_matches_clients_and_accepts_proxyjump_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            _, clients, _, _ = orchestration.load_config(
                self.write_json(directory, "workload.json", self.workload()))
            inventory = ssh.load_inventory(self.write_json(directory, "inventory.json", self.inventory()), clients)
        self.assertEqual(inventory.hosts["a"].alias, "sciera-rnp")
        self.assertEqual(inventory.client_hosts["hummingbird-1"], "b")
        self.assertEqual(inventory.shaping[0].baseline, "noqueue")

    def test_rejects_missing_client_placement(self):
        with tempfile.TemporaryDirectory() as directory:
            _, clients, _, _ = orchestration.load_config(
                self.write_json(directory, "workload.json", self.workload()))
            inventory = self.inventory()
            del inventory["placements"]["clients"]["best-effort-1"]
            with self.assertRaisesRegex(orchestration.ConfigError, "placements"):
                ssh.load_inventory(self.write_json(directory, "inventory.json", inventory), clients)

    def test_ssh_command_keeps_alias_as_ssh_destination(self):
        host = ssh.SSHHost("a", "sciera-rnp", "127.0.0.1:30255", "/var/tmp/humm", None)
        with mock.patch.object(ssh.subprocess, "run") as run:
            ssh.ssh_command(host, "true")
        self.assertEqual(run.call_args.args[0][:4], ["ssh", "--", "sciera-rnp", "sh"])

    def test_launch_never_places_jwt_in_ssh_arguments(self):
        host = ssh.SSHHost("a", "sciera-rnp", "127.0.0.1:30255", "/var/tmp/humm", None)
        with tempfile.TemporaryDirectory() as directory, \
             mock.patch.object(ssh.subprocess, "Popen") as popen:
            ssh.launch(host, "run-1", "client", ["ignored", "-mode", "client"],
                       Path(directory) / "client.log", "/var/tmp/humm/run-1/marketplace.jwt")
        command = popen.call_args.args[0]
        self.assertNotIn("jwt-value", command)
        self.assertIn("marketplace.jwt", command[-1])


if __name__ == "__main__":
    unittest.main()
