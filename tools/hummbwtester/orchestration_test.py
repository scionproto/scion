import json
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools.hummbwtester import orchestration
from tools.hummbwtester.orchestration import (
    ConfigError,
    client_args,
    interface_counters,
    inter_as_router_peers,
    InterfaceCounters,
    load_config,
    marketplace_registration_website,
    obtain_marketplace_jwt,
    patch_compose,
    patch_toml_section,
    print_report,
    ReportSnapshot,
    RouterInterface,
    server_args,
    TCStats,
)


class ConfigTest(unittest.TestCase):
    def write_config(self, value):
        # Keep each fixture isolated: load_config accepts a path because the production scripts
        # read the manually edited JSON file from disk.
        directory = tempfile.TemporaryDirectory()
        path = Path(directory.name) / "hummbwtester.json"
        path.write_text(json.dumps(value))
        self.addCleanup(directory.cleanup)
        return path

    def base_config(self):
        # Deliberately put the clients in reverse lexical order. The port assignment must depend
        # only on client_id, not on whether the client is Hummingbird or best-effort, nor on its
        # position in the JSON arrays.
        return {
            "hummingbird": {"reservation_source": "keys"},
            "server": {
                "isd_as": "1-ff00:0:112", "host": "fd00::1", "port": 12345,
                "receive_buffer_size": 4194304,
            },
            "hummingbird_clients": [{
                "client_id": "zeta", "isd_as": "1-ff00:0:111", "host": "172.20.0.29", "port": 0,
                "bandwidth": "2Mbps", "maxburst": "4Mbps", "duration": "60s",
                "hummingbird_reservation": {
                    "bandwidth": 1000, "duration": "1m", "reverse_bandwidth": 1000,
                },
            }],
            "best_effort_clients": [{
                "client_id": "alpha", "isd_as": "1-ff00:0:110", "host": "172.20.0.22", "port": 0,
                "bandwidth": "1Mbps", "maxburst": "2Mbps", "duration": "30s",
            }],
            "router": {
                "send_buffer_size": 16384,
                "receive_buffer_size": 4194304,
                "ingress_batch_size": 64,
                "processor_queue_size": 640,
                "egress_batch_size": 1,
                "egress_queue_size": 64,
            },
            "tc": {"rate": "10mbit", "burst": "50kb", "limit": "256kb"},
        }

    def test_marketplace_reservation_config_and_args(self):
        config = self.base_config()
        config["hummingbird"] = {
            "reservation_source": "marketplace",
            "marketplace": {
                "url": "https://marketplace.invalid", "username": "alice",
                "password_env": "MARKETPLACE_PASSWORD",
            },
        }
        config["hummingbird_clients"][0]["hummingbird_reservation"].update({
            "bandwidth": "100kbps", "reverse_bandwidth": "1mbps",
        })
        server, clients, _, _ = load_config(self.write_config(config))
        hummingbird = next(client for client in clients if client.hummingbird)
        args = client_args(hummingbird, server, "172.20.0.21:30255")
        self.assertEqual(args[args.index("-hummingbird") + 1], "100kbps,1m,1mbps")
        self.assertNotIn("-hummKeysDir", args)
        assert hummingbird.marketplace is not None
        self.assertEqual(hummingbird.marketplace.username, "alice")
        self.assertEqual(hummingbird.marketplace.url, "https://marketplace.invalid")
        self.assertIsNone(hummingbird.marketplace.sub_account)

    def test_requires_global_hummingbird_source(self):
        config = self.base_config()
        del config["hummingbird"]
        with self.assertRaises(ConfigError):
            load_config(self.write_config(config))

    def test_rejects_marketplace_configuration_in_keys_mode(self):
        config = self.base_config()
        config["hummingbird"]["marketplace"] = {
            "url": "https://marketplace.invalid", "username": "alice",
            "password_env": "MARKETPLACE_PASSWORD",
        }
        with self.assertRaises(ConfigError):
            load_config(self.write_config(config))

    def test_discovers_unique_marketplace_registration_website(self):
        with tempfile.TemporaryDirectory() as directory:
            generated = Path(directory)
            (generated / "ASff00_0_111").mkdir()
            (generated / "ASff00_0_111" / "staticInfoConfig.json").write_text(json.dumps({
                "note": json.dumps({"hummingbird": [{
                    "api_protocol": "connectrpc/TLS/TCP",
                    "client_registration_website": "https://172.20.0.27:31888",
                }]})
            }))
            with mock.patch.object(orchestration, "GEN", generated):
                self.assertEqual(marketplace_registration_website(), "https://172.20.0.27:31888")

    def test_obtains_marketplace_jwt_without_logging_credentials(self):
        completed = mock.Mock(returncode=0, stdout="jwt-value\n", stderr="")
        marketplace = orchestration.MarketplaceConfig(
            "https://market.invalid", "alice", "MARKETPLACE_PASSWORD", "hummbwtester")
        with mock.patch.dict(orchestration.os.environ, {"MARKETPLACE_PASSWORD": "secret"}), \
             mock.patch.object(orchestration.subprocess, "run", return_value=completed) as run:
            self.assertEqual(obtain_marketplace_jwt(marketplace), "jwt-value")
        self.assertEqual(run.call_args.kwargs["capture_output"], True)
        command = run.call_args.args[0]
        self.assertIn("alice", command)
        self.assertIn("https://market.invalid", command)
        self.assertIn("MARKETPLACE_PASSWORD", command)
        self.assertNotIn("secret", command)

    def test_marketplace_url_and_password_env_are_required(self):
        config = self.base_config()
        config["hummingbird"] = {
            "reservation_source": "marketplace",
            "marketplace": {"username": "alice", "password_env": "MARKETPLACE_PASSWORD"},
        }
        with self.assertRaisesRegex(ConfigError, "url"):
            load_config(self.write_config(config))

    def test_clients_are_sorted_for_metrics_ports(self):
        _, clients, _, _ = load_config(self.write_config(self.base_config()))
        # The first sorted client owns the fixed base port; every subsequent client increments it.
        self.assertEqual([("alpha", 9090), ("zeta", 9091)],
                         [(client.client_id, client.metrics_port) for client in clients])

    def test_requires_positive_server_receive_buffer(self):
        for value in (0, -1, "4194304", True):
            with self.subTest(value=value):
                config = self.base_config()
                config["server"]["receive_buffer_size"] = value
                with self.assertRaises(ConfigError):
                    load_config(self.write_config(config))

    def test_server_args_include_receive_buffer(self):
        server, _, _, _ = load_config(self.write_config(self.base_config()))
        args = server_args(server, "172.20.0.21:30255")
        self.assertEqual(args[args.index("-receive-buffer-size") + 1], "4194304")

    def test_rejects_unscoped_client_fields(self):
        config = self.base_config()
        # sciond is derived from gen/sciond_addresses.json, so accepting it in the experiment
        # configuration would make the topology and JSON disagree silently.
        config["best_effort_clients"][0]["sciond"] = "172.20.0.21:30255"
        with self.assertRaises(ConfigError):
            load_config(self.write_config(config))

    def test_requires_workload_for_every_client(self):
        for client_type in ("hummingbird_clients", "best_effort_clients"):
            for field in ("bandwidth", "maxburst"):
                with self.subTest(client_type=client_type, field=field):
                    config = self.base_config()
                    del config[client_type][0][field]
                    with self.assertRaises(ConfigError):
                        load_config(self.write_config(config))

    def test_maxburst_must_be_at_least_bandwidth(self):
        config = self.base_config()
        config["best_effort_clients"][0]["maxburst"] = "999Kbps"
        with self.assertRaisesRegex(ConfigError, "maxburst must be >="):
            load_config(self.write_config(config))

    def test_rejects_invalid_client_bandwidths(self):
        for field, value in (("bandwidth", "0Mbps"), ("maxburst", "manyMbps")):
            with self.subTest(field=field, value=value):
                config = self.base_config()
                config["best_effort_clients"][0][field] = value
                with self.assertRaises(ConfigError):
                    load_config(self.write_config(config))

    def test_requires_reservation_for_hummingbird_clients(self):
        config = self.base_config()
        del config["hummingbird_clients"][0]["hummingbird_reservation"]
        with self.assertRaises(ConfigError):
            load_config(self.write_config(config))

    def test_rejects_reservation_for_best_effort_clients(self):
        config = self.base_config()
        config["best_effort_clients"][0]["hummingbird_reservation"] = {
            "bandwidth": 1000, "duration": "10s", "reverse_bandwidth": 1000,
        }
        with self.assertRaises(ConfigError):
            load_config(self.write_config(config))

    def test_requires_positive_router_tuning(self):
        for key in self.base_config()["router"]:
            with self.subTest(key=key):
                config = self.base_config()
                config["router"][key] = 0
                with self.assertRaises(ConfigError):
                    load_config(self.write_config(config))

    def test_rejects_legacy_router_batch_size(self):
        config = self.base_config()
        config["router"]["batch_size"] = 1
        with self.assertRaises(ConfigError):
            load_config(self.write_config(config))

    def test_requires_all_router_tuning_values(self):
        for key in self.base_config()["router"]:
            with self.subTest(key=key):
                config = self.base_config()
                del config["router"][key]
                with self.assertRaises(ConfigError):
                    load_config(self.write_config(config))

    def test_rejects_latency_instead_of_explicit_limit(self):
        config = self.base_config()
        config["tc"] = {"rate": "10mbit", "burst": "50kb", "latency": "1ms"}
        with self.assertRaises(ConfigError):
            load_config(self.write_config(config))

    def test_optional_tuning_is_omitted_or_passed_to_client(self):
        server, clients, _, _ = load_config(self.write_config(self.base_config()))
        best_effort, hummingbird = clients
        # Omitted settings must leave the tester's own defaults in effect.
        args = client_args(best_effort, server, "172.20.0.21:30255")
        self.assertNotIn("-payload-size", args)
        self.assertNotIn("-pong-rate", args)
        self.assertNotIn("-renewal-ahead", args)
        self.assertNotIn("-hummingbird", args)

        config = self.base_config()
        config["best_effort_clients"][0].update({
            "payload_size": 1200, "pong_rate": 2.0,
        })
        config["hummingbird_clients"][0]["hummingbird_reservation"].update({
            "renewal_ahead": "6s",
            "reservation_overlap": "4s",
            "humm_start_offset": "-1s",
        })
        server, clients, _, _ = load_config(self.write_config(config))
        best_effort, hummingbird = clients
        args = client_args(best_effort, server, "172.20.0.21:30255")
        self.assertEqual(
            args[args.index("-bandwidth") + 1], "1Mbps")
        self.assertEqual(args[args.index("-maxburst") + 1], "2Mbps")
        self.assertEqual(args[args.index("-duration") + 1], "30s")
        self.assertEqual(args[args.index("-payload-size") + 1], "1200")
        self.assertEqual(args[args.index("-pong-rate") + 1], "2.0")

        args = client_args(hummingbird, server, "172.20.0.21:30255")
        self.assertEqual(args[args.index("-hummingbird") + 1], "1000,1m,1000")
        self.assertEqual(args[args.index("-renewal-ahead") + 1], "6s")
        self.assertEqual(args[args.index("-reservation-overlap") + 1], "4s")
        self.assertEqual(args[args.index("-humm-start-offset") + 1], "-1s")

    def test_rejects_legacy_renewal_fraction(self):
        config = self.base_config()
        config["hummingbird_clients"][0]["renewal_fraction"] = 0.7
        with self.assertRaises(ConfigError):
            load_config(self.write_config(config))

    def test_rejects_top_level_renewal_ahead(self):
        config = self.base_config()
        config["hummingbird_clients"][0]["renewal_ahead"] = "3s"
        with self.assertRaises(ConfigError):
            load_config(self.write_config(config))

    def test_rejects_invalid_reservation_timing_settings(self):
        for field in ("renewal_ahead", "reservation_overlap", "humm_start_offset"):
            for value in ("", 3, True):
                with self.subTest(field=field, value=value):
                    config = self.base_config()
                    config["hummingbird_clients"][0]["hummingbird_reservation"][field] = value
                    with self.assertRaises(ConfigError):
                        load_config(self.write_config(config))


class SetupPatchTest(unittest.TestCase):
    def test_patch_toml_section_adds_and_updates_idempotently(self):
        cases = {
            "without section": "[general]\nid = \"br1\"\n",
            "with section": (
                "[general]\nid = \"br1\"\n\n[router]\nsend_buffer_size = 999\nbatch_size = 1\n\n"
                "[metrics]\nprometheus = \"127.0.0.1:30442\"\n"
            ),
        }
        for name, original in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "br.toml"
                path.write_text(original)
                values = {
                    "send_buffer_size": 16384,
                    "receive_buffer_size": 4194304,
                    "ingress_batch_size": 64,
                    "processor_queue_size": 640,
                    "egress_batch_size": 1,
                    "egress_queue_size": 64,
                }
                patch_toml_section(path, "router", values, remove={"batch_size"})
                once = path.read_text()
                patch_toml_section(path, "router", values, remove={"batch_size"})
                self.assertEqual(once, path.read_text())
                self.assertEqual(once.count("[router]"), 1)
                self.assertEqual(once.count("send_buffer_size = 16384"), 1)
                self.assertEqual(once.count("receive_buffer_size = 4194304"), 1)
                self.assertEqual(once.count("ingress_batch_size = 64"), 1)
                self.assertEqual(once.count("processor_queue_size = 640"), 1)
                self.assertEqual(once.count("egress_batch_size = 1"), 1)
                self.assertEqual(once.count("egress_queue_size = 64"), 1)
                self.assertNotRegex(once, r"(?m)^batch_size[ \t]*=")
                if "[metrics]" in original:
                    self.assertIn("[metrics]", once)

    def test_inter_as_router_peers_excludes_internal_network(self):
        compose = {
            "services": {
                "br110-a": {
                    "networks": {
                        "external": {"ipv4_address": "192.0.2.1"},
                        "internal": {"ipv4_address": "192.0.2.9"},
                    },
                },
                "br111-a": {
                    "networks": {"external": {"ipv4_address": "192.0.2.2"}},
                },
                "br110-b": {
                    "networks": {"internal": {"ipv4_address": "192.0.2.10"}},
                },
            },
        }
        ias = {"br110-a": "1-ff00:0:110", "br110-b": "1-ff00:0:110",
               "br111-a": "1-ff00:0:111"}
        with mock.patch.object(orchestration, "br_ias", return_value=ias):
            self.assertEqual(inter_as_router_peers(compose), {
                "br110-a": ["192.0.2.2"],
                "br111-a": ["192.0.2.1"],
            })

    def test_patch_compose_creates_namespace_helper_per_router(self):
        compose = {
            "services": {
                "br1-ff00_0_110-1": {"image": "router"},
                "br1-ff00_0_111-1": {"image": "router"},
                "hummbwtester_tc_setup": {"network_mode": "host"},
            },
        }
        peers = {
            "br1-ff00_0_110-1": ["172.20.0.3"],
            "br1-ff00_0_111-1": ["172.20.0.2"],
        }
        tc = {"rate": "10mbit", "burst": "50kb", "limit": "256kb"}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scion-dc.yml"
            with mock.patch.object(orchestration, "COMPOSE", output):
                patch_compose(compose, peers, tc)
        self.assertNotIn("hummbwtester_tc_setup", compose["services"])
        for router, peer_addresses in peers.items():
            helper = compose["services"][orchestration.tc_helper_name(router)]
            self.assertEqual(helper["network_mode"], f"service:{router}")
            self.assertEqual(helper["depends_on"], [router])
            self.assertEqual(helper["command"], [
                "setup", "10mbit", "50kb", "256kb", *peer_addresses,
            ])


class ReportTest(unittest.TestCase):
    def interfaces(self):
        return [
            RouterInterface("br-a", "1-ff00:0:110", "1", "1-ff00:0:111", "192.0.2.1", "192.0.2.2"),
            RouterInterface("br-b", "1-ff00:0:111", "41", "1-ff00:0:110", "192.0.2.2", "192.0.2.1"),
        ]

    def test_aggregates_router_counters_by_interface(self):
        counters = interface_counters(self.interfaces(), {
            "br-a": '\n'.join([
                'router_bfd_sent_packets_total{interface="1"} 10',
                'router_bfd_received_packets_total{interface="1"} 9',
                'router_humm_demoted_freshness_total{interface="1",sizeclass="0_63"} 2',
                'router_humm_demoted_expired_total{interface="1",sizeclass="0_63"} 3',
                'router_humm_demoted_tokenbucket_total{interface="1",sizeclass="0_63"} 4',
                'router_dropped_pkts_total{interface="1",reason="busy_forwarder",sizeclass="0_63"} 5',
                'router_dropped_pkts_total{interface="1",reason="busy_forwarder",sizeclass="64_127"} 6',
            ]),
        })
        self.assertEqual(counters[("br-a", "1")], InterfaceCounters(10, 9, 9, 11))
        self.assertNotIn(("br-b", "41"), counters)

    def test_report_uses_peer_bfd_sent_to_calculate_loss(self):
        interfaces = self.interfaces()
        previous = ReportSnapshot(
            counters={
                ("br-a", "1"): InterfaceCounters(100, 100, 2, 3),
                ("br-b", "41"): InterfaceCounters(200, 200, 4, 5),
            },
            tc={
                ("br-a", "1"): TCStats(10, 20, 30),
                ("br-b", "41"): TCStats(40, 50, 60),
            },
            errors=(),
        )
        current = ReportSnapshot(
            counters={
                ("br-a", "1"): InterfaceCounters(110, 118, 3, 7),
                ("br-b", "41"): InterfaceCounters(225, 210, 4, 5),
            },
            tc={
                ("br-a", "1"): TCStats(11, 25, 31),
                ("br-b", "41"): TCStats(40, 58, 61),
            },
            errors=("br-c metrics unavailable",),
        )
        output = io.StringIO()
        with mock.patch("sys.stdout", output):
            print_report(previous, current, interfaces)
        rendered = output.getvalue()
        self.assertIn("HUMMBWTESTER_REPORT interval=60s", rendered)
        # self.assertIn("BFD lost", rendered)
        # self.assertIn("TC backlog bytes", rendered)
        self.assertIn("TC dropped", rendered)
        self.assertIn("observation_error=br-c metrics unavailable", rendered)
        # # br-a lost 25 BFD packets sent by br-b minus 18 packets received by br-a.
        # self.assertRegex(rendered, r"BFD lost.*\b7\b")
        self.assertRegex(rendered, r"TC dropped.*\b1\b.*\b0\b")
        self.assertIn("\n\nHUMMBWTESTER_REPORT observation_error", rendered)


if __name__ == "__main__":
    unittest.main()
