#!/usr/bin/env python3
"""Docker orchestration for the local hummbwtester experiment.

Endpoint placement and reservation-source settings come from JSON. Everything else is derived from
the generated Docker topology so that a stopped topology can be brought back with the same setup.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import urllib.request
from dataclasses import dataclass, replace
from typing import Any

import yaml


# This module lives in tools/hummbwtester/, so two parents up is the repository root.
ROOT = Path(__file__).resolve().parents[2]
GEN = ROOT / "gen"
COMPOSE = GEN / "scion-dc.yml"
SCIOND_ADDRESSES = GEN / "sciond_addresses.json"
CONFIG_DEFAULT = ROOT / "tools" / "hummbwtester" / "hummbwtester.json"
BIN = ROOT / "bin" / "hummbwtester"
TC_SCRIPT = ROOT / "tools" / "hummbwtester" / "tc_setup.sh"
TARGET_DIR = GEN / "hummbwtester-prometheus"
# Metrics ports are intentionally derived rather than stored in the JSON file.
METRICS_BASE_PORT = 9090
CLIENT_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
TC_VALUE_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?(?:bit|kbit|mbit|gbit|b|kb|mb|gb|ms|us|s)?$", re.I)
TC_HELPER_PREFIX = "hummbwtester_tc_"
TC_STATS_RE = re.compile(
    r"^HUMMBWTESTER_TC_STATS peer=(\S+) dev=(\S+) dropped=(\d+) overlimits=(\d+) "
    r"backlog_bytes=(\d+)$",
)
PROMETHEUS_LABEL_RE = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"])*)"')


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Endpoint:
    # A SCION UDP endpoint as represented in the JSON file. frozen=True makes these parsed
    # configuration values immutable after validation.
    isd_as: str
    host: str
    port: int
    # Only the server endpoint sets this; client endpoints keep the zero default.
    receive_buffer_size: int = 0

    def local(self) -> str:
        return f"{self.isd_as},{join_host_port(self.host, self.port)}"


@dataclass(frozen=True)
class HummingbirdReservation:
    bandwidth: int | str
    duration: str
    reverse_bandwidth: int | str
    renewal_ahead: str | None
    reservation_overlap: str | None
    humm_start_offset: str | None


@dataclass(frozen=True)
class MarketplaceConfig:
    """The non-secret marketplace identity and location for one workload."""

    url: str
    username: str
    password_env: str
    sub_account: str | None


@dataclass(frozen=True)
class Client:
    # The runner adds the derived metric port and the client kind to the JSON configuration.
    client_id: str
    endpoint: Endpoint
    hummingbird: bool
    metrics_port: int
    bandwidth: str
    maxburst: str
    duration: str
    hummingbird_reservation: HummingbirdReservation | None
    payload_size: int | None
    pong_rate: float | int | None
    reservation_source: str
    marketplace: MarketplaceConfig | None


@dataclass(frozen=True)
class RouterInterface:
    """One external border-router interface and its underlay peer."""

    router: str
    isd_as: str
    interface: str
    neighbor_isd_as: str
    local: str
    remote: str

    @property
    def key(self) -> tuple[str, str]:
        return self.router, self.interface

    @property
    def label(self) -> str:
        return f"{self.router}#{self.interface}"


@dataclass(frozen=True)
class InterfaceCounters:
    """Cumulative router counters reported for one external interface."""

    bfd_sent: int = 0
    bfd_received: int = 0
    demotions: int = 0
    busy_forwarder_drops: int = 0


@dataclass(frozen=True)
class TCStats:
    """Cumulative TBF counters and instantaneous backlog for one egress device."""

    dropped: int
    overlimits: int
    backlog_bytes: int


@dataclass(frozen=True)
class ReportSnapshot:
    """One observation used to produce the next per-minute report."""

    counters: dict[tuple[str, str], InterfaceCounters]
    tc: dict[tuple[str, str], TCStats]
    errors: tuple[str, ...]


def join_host_port(host: str, port: int) -> str:
    """Format an IP address and port, adding brackets for IPv6 addresses."""
    return f"[{host}]:{port}" if ipaddress.ip_address(host).version == 6 else f"{host}:{port}"


def tester_service(ia: str) -> str:
    """Return the generated Docker Compose tester service name for an IA."""
    return "tester_" + ia.replace(":", "_")


def read_json(path: Path) -> dict[str, Any]:
    """Load a JSON object from path and turn parsing failures into ConfigError."""
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as err:
        raise ConfigError(f"reading {path}: {err}") from err
    if not isinstance(value, dict):
        raise ConfigError("configuration root must be an object")
    return value


def require_fields(
    value: dict[str, Any], required: set[str], context: str, optional: set[str] | None = None,
) -> None:
    """Require value to contain required keys and no keys outside optional, with useful errors."""
    # Exact field matching prevents stale, unsupported configuration from being silently ignored.
    got = set(value)
    allowed = required | (optional or set())
    if not required <= got or not got <= allowed:
        missing = sorted(required - got)
        extra = sorted(got - allowed)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unknown " + ", ".join(extra))
        raise ConfigError(f"{context} has " + "; ".join(detail))


def parse_endpoint(
    value: dict[str, Any], context: str, *, require_receive_buffer: bool = False,
) -> Endpoint:
    """Validate one JSON endpoint object and return its typed representation."""
    required = {"isd_as", "host", "port"}
    if require_receive_buffer:
        required.add("receive_buffer_size")
    require_fields(value, required, context)
    ia, host, port = value["isd_as"], value["host"], value["port"]
    if not isinstance(ia, str) or not ia:
        raise ConfigError(f"{context}.isd_as must be a non-empty string")
    if not isinstance(host, str):
        raise ConfigError(f"{context}.host must be an IP address")
    try:
        ipaddress.ip_address(host)
    except ValueError as err:
        raise ConfigError(f"{context}.host is not an IP address: {host}") from err
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise ConfigError(f"{context}.port must be an integer from 0 through 65535")
    receive_buffer_size = value.get("receive_buffer_size", 0)
    if (not isinstance(receive_buffer_size, int) or isinstance(receive_buffer_size, bool)
            or receive_buffer_size < 0):
        raise ConfigError(f"{context}.receive_buffer_size must be a non-negative integer")
    if require_receive_buffer and receive_buffer_size == 0:
        raise ConfigError(f"{context}.receive_buffer_size must be a positive integer")
    return Endpoint(ia, host, port, receive_buffer_size)


def parse_client(
    entry: dict[str, Any], hummingbird: bool, context: str, reservation_source: str,
    marketplace: MarketplaceConfig | None,
) -> Client:
    """Validate one client configuration and retain its workload and optional tuning settings."""
    required = {"client_id", "isd_as", "host", "port", "bandwidth", "maxburst", "duration"}
    optional = {"payload_size", "pong_rate"}
    if hummingbird:
        required.add("hummingbird_reservation")
    require_fields(entry, required, context, optional)

    client_id = entry["client_id"]
    if not isinstance(client_id, str) or not CLIENT_ID_RE.fullmatch(client_id):
        raise ConfigError(f"{context}.client_id must match {CLIENT_ID_RE.pattern}")
    for key in ("bandwidth", "maxburst", "duration"):
        if not isinstance(entry[key], str) or not entry[key]:
            raise ConfigError(f"{context}.{key} must be a non-empty string")
    bandwidth = parse_bandwidth(entry["bandwidth"], f"{context}.bandwidth")
    maxburst = parse_bandwidth(entry["maxburst"], f"{context}.maxburst")
    if maxburst < bandwidth:
        raise ConfigError(f"{context}.maxburst must be >= {context}.bandwidth")

    reservation: HummingbirdReservation | None = None
    if hummingbird:
        value = entry["hummingbird_reservation"]
        if not isinstance(value, dict):
            raise ConfigError(f"{context}.hummingbird_reservation must be an object")
        require_fields(value, {"bandwidth", "duration", "reverse_bandwidth"},
                       f"{context}.hummingbird_reservation",
                       {"renewal_ahead", "reservation_overlap", "humm_start_offset"})
        reservation_bandwidth, duration, reverse_bandwidth = (
            value["bandwidth"], value["duration"], value["reverse_bandwidth"])
        validate_reservation_bandwidth(
            reservation_bandwidth, reservation_source,
            f"{context}.hummingbird_reservation.bandwidth")
        if not isinstance(duration, str) or not duration:
            raise ConfigError(f"{context}.hummingbird_reservation.duration must be a non-empty string")
        validate_reservation_bandwidth(
            reverse_bandwidth, reservation_source,
            f"{context}.hummingbird_reservation.reverse_bandwidth")
        timing = {}
        for key in ("renewal_ahead", "reservation_overlap", "humm_start_offset"):
            setting = value.get(key)
            if setting is not None and (not isinstance(setting, str) or not setting):
                raise ConfigError(
                    f"{context}.hummingbird_reservation.{key} "
                    "must be a non-empty duration string")
            timing[key] = setting
        reservation = HummingbirdReservation(
            bandwidth=reservation_bandwidth,
            duration=duration,
            reverse_bandwidth=reverse_bandwidth,
            renewal_ahead=timing["renewal_ahead"],
            reservation_overlap=timing["reservation_overlap"],
            humm_start_offset=timing["humm_start_offset"],
        )

    payload_size = entry.get("payload_size")
    if payload_size is not None and (not isinstance(payload_size, int) or isinstance(payload_size, bool)):
        raise ConfigError(f"{context}.payload_size must be an integer")
    pong_rate = entry.get("pong_rate")
    if pong_rate is not None and (not isinstance(pong_rate, (int, float)) or isinstance(pong_rate, bool)):
        raise ConfigError(f"{context}.pong_rate must be a number")
    return Client(
        client_id=client_id,
        endpoint=parse_endpoint({key: entry[key] for key in ("isd_as", "host", "port")}, context),
        hummingbird=hummingbird,
        metrics_port=0,
        bandwidth=entry["bandwidth"],
        maxburst=entry["maxburst"],
        duration=entry["duration"],
        hummingbird_reservation=reservation,
        payload_size=payload_size,
        pong_rate=pong_rate,
        reservation_source=reservation_source,
        marketplace=marketplace,
    )


def validate_reservation_bandwidth(value: Any, source: str, context: str) -> None:
    """Validate a key-derived class or marketplace bandwidth accepted by the Go client."""
    if source == "keys":
        if (not isinstance(value, int) or isinstance(value, bool)
                or not 0 <= value <= 65535):
            raise ConfigError(f"{context} must be an integer from 0 through 65535 in keys mode")
        return
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{context} must be a unit-bearing string in marketplace mode")
    match = re.fullmatch(r"([0-9]+)\s*(kbps|mbps|gbps)", value.strip(), re.IGNORECASE)
    if not match:
        raise ConfigError(f"{context} must use kbps, mbps, or gbps in marketplace mode")
    amount = int(match.group(1)) * {"kbps": 1, "mbps": 1000, "gbps": 1000_000}[match.group(2).lower()]
    if amount > 2**32 - 1:
        raise ConfigError(f"{context} is too large in marketplace mode")


def parse_bandwidth(value: str, context: str) -> float:
    """Parse the bandwidth syntax accepted by the Go client and require a usable positive rate."""
    factors = (("Gbps", 1e9), ("Mbps", 1e6), ("Kbps", 1e3), ("bps", 1.0))
    number = value.strip()
    factor = 1.0
    for suffix, candidate in factors:
        if number.endswith(suffix):
            number = number[:-len(suffix)]
            factor = candidate
            break
    try:
        result = float(number) * factor
    except ValueError as err:
        raise ConfigError(f"{context} is not a valid bandwidth: {value}") from err
    if not math.isfinite(result) or result <= 0:
        raise ConfigError(f"{context} must be finite and positive")
    return result


def load_config(path: Path) -> tuple[Endpoint, list[Client], dict[str, int], dict[str, str]]:
    """Parse experiment JSON and derive sorted clients, metrics ports, and tc settings."""
    root = read_json(path)
    require_fields(
        root,
        {"server", "hummingbird", "hummingbird_clients", "best_effort_clients", "router", "tc"},
        "configuration",
    )
    hummingbird_config = root["hummingbird"]
    if not isinstance(hummingbird_config, dict):
        raise ConfigError("hummingbird must be an object")
    require_fields(hummingbird_config, {"reservation_source"}, "hummingbird", {"marketplace"})
    reservation_source = hummingbird_config["reservation_source"]
    if reservation_source not in ("keys", "marketplace"):
        raise ConfigError("hummingbird.reservation_source must be \"keys\" or \"marketplace\"")
    marketplace_config: MarketplaceConfig | None = None
    if reservation_source == "marketplace":
        marketplace = hummingbird_config.get("marketplace")
        if not isinstance(marketplace, dict):
            raise ConfigError("hummingbird.marketplace is required in marketplace mode")
        require_fields(marketplace, {"url", "username", "password_env"},
                       "hummingbird.marketplace", {"sub_account"})
        url, username, password_env = (
            marketplace["url"], marketplace["username"], marketplace["password_env"])
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            raise ConfigError("hummingbird.marketplace.url must be an HTTP(S) URL")
        if not isinstance(username, str) or not username:
            raise ConfigError("hummingbird.marketplace.username must be a non-empty string")
        if (not isinstance(password_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", password_env)):
            raise ConfigError("hummingbird.marketplace.password_env must name an environment variable")
        sub_account = marketplace.get("sub_account")
        if sub_account is not None and (not isinstance(sub_account, str) or not sub_account):
            raise ConfigError("hummingbird.marketplace.sub_account must be a non-empty string")
        marketplace_config = MarketplaceConfig(url, username, password_env, sub_account)
    elif "marketplace" in hummingbird_config:
        raise ConfigError("hummingbird.marketplace is only valid in marketplace mode")
    if not isinstance(root["server"], dict):
        raise ConfigError("server must be an object")
    server = parse_endpoint(root["server"], "server", require_receive_buffer=True)
    if server.port == 0:
        raise ConfigError("server.port must not be zero")

    # Merge both client lists so a single ordering determines metrics ports across all clients.
    raw_clients: list[tuple[dict[str, Any], bool, str]] = []
    for key, hummingbird in (("hummingbird_clients", True), ("best_effort_clients", False)):
        entries = root[key]
        if not isinstance(entries, list):
            raise ConfigError(f"{key} must be an array")
        for index, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ConfigError(f"{key}[{index}] must be an object")
            raw_clients.append((entry, hummingbird, f"{key}[{index}]"))
    if not raw_clients:
        raise ConfigError("at least one client is required")

    parsed: list[Client] = []
    for entry, hummingbird, context in raw_clients:
        parsed.append(parse_client(entry, hummingbird, context, reservation_source,
                                   marketplace_config))
    # Sorting makes a client's metrics port stable when the JSON array order changes.
    parsed.sort(key=lambda item: item.client_id)
    if len({item.client_id for item in parsed}) != len(parsed):
        raise ConfigError("client_id values must be unique")
    if METRICS_BASE_PORT + len(parsed) - 1 > 65535:
        raise ConfigError("too many clients for the derived Prometheus port range")
    clients = [replace(client, metrics_port=METRICS_BASE_PORT + index)
               for index, client in enumerate(parsed)]

    router = root["router"]
    if not isinstance(router, dict):
        raise ConfigError("router must be an object")
    router_keys = {
        "send_buffer_size",
        "receive_buffer_size",
        "ingress_batch_size",
        "processor_queue_size",
        "egress_batch_size",
        "egress_queue_size",
    }
    require_fields(router, router_keys, "router")
    for key in router_keys:
        value = router[key]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ConfigError(f"router.{key} must be a positive integer")

    tc = root["tc"]
    if not isinstance(tc, dict):
        raise ConfigError("tc must be an object")
    require_fields(tc, {"rate", "burst", "limit"}, "tc")
    for key, value in tc.items():
        if not isinstance(value, str) or not TC_VALUE_RE.fullmatch(value):
            raise ConfigError(f"tc.{key} is not a safe tc value")
    return (
        server,
        clients,
        {key: router[key] for key in sorted(router_keys)},
        {key: tc[key] for key in ("rate", "burst", "limit")},
    )


def compose_data() -> dict[str, Any]:
    """Load the existing generated Docker Compose configuration without regenerating it."""
    # setup operates on an already generated Docker topology; it must not regenerate gen/.
    if not COMPOSE.is_file():
        raise ConfigError("gen/scion-dc.yml is missing; generate Docker tiny manually with "
                          "./scion.sh topology -d -c topology/tiny.topo")
    if not SCIOND_ADDRESSES.is_file():
        raise ConfigError("gen/sciond_addresses.json is missing")
    try:
        value = yaml.safe_load(COMPOSE.read_text())
    except (OSError, yaml.YAMLError) as err:
        raise ConfigError(f"reading {COMPOSE}: {err}") from err
    if not isinstance(value, dict) or not isinstance(value.get("services"), dict):
        raise ConfigError("gen/scion-dc.yml has no services section")
    return value


def sciond_map() -> dict[str, str]:
    """Load the generated mapping from ISD-AS strings to SCION daemon IP addresses."""
    try:
        value = json.loads(SCIOND_ADDRESSES.read_text())
    except (OSError, json.JSONDecodeError) as err:
        raise ConfigError(f"reading {SCIOND_ADDRESSES}: {err}") from err
    if not isinstance(value, dict):
        raise ConfigError("sciond address map is invalid")
    if not all(isinstance(ia, str) and isinstance(host, str) for ia, host in value.items()):
        raise ConfigError("sciond address map contains non-string entries")
    return value


def endpoint_sciond(endpoint: Endpoint, addresses: dict[str, str]) -> str:
    """Derive the bracketed SCION daemon connector for endpoint's AS."""
    # The generated file stores only the daemon IP. SCION daemons use the fixed API port 30255.
    try:
        return join_host_port(addresses[endpoint.isd_as], 30255)
    except KeyError as err:
        raise ConfigError(f"no sciond address for {endpoint.isd_as}") from err


def validate_endpoints(compose: dict[str, Any], server: Endpoint, clients: list[Client]) -> None:
    """Ensure every configured endpoint belongs to the generated tester for its AS."""
    # A configured endpoint must be the tester address of its AS, not an arbitrary container IP.
    services = compose["services"]
    for endpoint, context in [(server, "server")] + [(client.endpoint, client.client_id) for client in clients]:
        service = tester_service(endpoint.isd_as)
        entry = services.get(service)
        if not isinstance(entry, dict):
            raise ConfigError(f"{context}: tester service {service} is absent from generated topology")
        environment = entry.get("environment", {})
        if not isinstance(environment, dict) or environment.get("SCION_LOCAL_ADDR") != endpoint.host:
            raise ConfigError(f"{context}: host {endpoint.host} does not match {service} SCION_LOCAL_ADDR")


def br_ias() -> dict[str, str]:
    """Map generated border-router service names to their authoritative topology IAs."""
    # Compose service names alone do not reliably identify an AS, so topology.json is authoritative.
    result: dict[str, str] = {}
    for topology in GEN.glob("AS*/topology.json"):
        data = json.loads(topology.read_text())
        ia = data.get("isd_as")
        for br in data.get("border_routers", {}):
            result[br] = ia
    return result


def br_config_paths() -> dict[str, Path]:
    """Map generated border-router service names to their TOML configuration files."""
    result: dict[str, Path] = {}
    for topology in GEN.glob("AS*/topology.json"):
        data = json.loads(topology.read_text())
        for br in data.get("border_routers", {}):
            path = topology.parent / f"{br}.toml"
            if not path.is_file():
                raise ConfigError(f"generated border-router config is missing: {path}")
            result[br] = path
    return result


def patch_toml_section(
    path: Path,
    section: str,
    values: dict[str, int],
    remove: set[str] | None = None,
) -> None:
    """Idempotently replace, insert, and remove integer keys in one TOML section."""
    text = path.read_text()
    section_match = re.search(rf"(?m)^\[{re.escape(section)}\][ \t]*(?:#.*)?$", text)
    rendered = [f"{key} = {value}" for key, value in values.items()]
    if section_match is None:
        separator = "" if not text or text.endswith("\n\n") else ("\n" if text.endswith("\n") else "\n\n")
        updated = text + separator + f"[{section}]\n" + "\n".join(rendered) + "\n"
    else:
        body_start = section_match.end()
        next_section = re.search(r"(?m)^\[[^\n]+\][ \t]*(?:#.*)?$", text[body_start:])
        body_end = body_start + next_section.start() if next_section else len(text)
        body = text[body_start:body_end]
        for key in remove or set():
            pattern = re.compile(rf"(?m)^[ \t]*{re.escape(key)}[ \t]*=.*\n?")
            body = pattern.sub("", body)
        missing: list[str] = []
        for key, value in values.items():
            pattern = re.compile(rf"(?m)^[ \t]*{re.escape(key)}[ \t]*=.*$")
            body, count = pattern.subn(f"{key} = {value}", body, count=1)
            if count == 0:
                missing.append(f"{key} = {value}")
        if missing:
            body = body.rstrip("\n") + "\n" + "\n".join(missing) + "\n"
        updated = text[:body_start] + body + text[body_end:]
    if updated != text:
        path.write_text(updated)


def patch_router_configs(router: dict[str, int]) -> None:
    """Apply experiment-only socket, batch, and queue settings to every generated BR."""
    configs = br_config_paths()
    if not configs:
        raise ConfigError("no generated border-router TOML files were found")
    for path in configs.values():
        # Earlier experiment runs added the deprecated common batch_size. Remove it so explicit
        # ingress and egress sizing is the only active experiment configuration.
        patch_toml_section(path, "router", router, remove={"batch_size"})


def compose_network_address(entry: Any, family: str) -> str | None:
    """Return one explicitly configured Compose endpoint address for an IP family."""
    if not isinstance(entry, dict):
        return None
    value = entry.get(f"{family}_address")
    return value if isinstance(value, str) else None


def inter_as_router_peers(compose: dict[str, Any]) -> dict[str, list[str]]:
    """Map each BR to peer addresses reachable through its inter-AS Docker networks."""
    attached: dict[str, list[str]] = {}
    for service, entry in compose["services"].items():
        if not service.startswith("br") or not isinstance(entry, dict):
            continue
        networks = entry.get("networks", {})
        if isinstance(networks, dict):
            for network in networks:
                attached.setdefault(network, []).append(service)
    ia_by_br = br_ias()
    result: dict[str, set[str]] = {}
    for network, routers in attached.items():
        # AS110 has two BRs on its internal bridge. Require different IAs to avoid shaping it.
        if len({ia_by_br.get(router) for router in routers}) <= 1:
            continue
        for router in routers:
            own_network = compose["services"][router]["networks"][network]
            for peer in routers:
                if peer == router or ia_by_br.get(peer) == ia_by_br.get(router):
                    continue
                peer_network = compose["services"][peer]["networks"][network]
                for family in ("ipv4", "ipv6"):
                    if (compose_network_address(own_network, family) is not None
                            and (peer_address := compose_network_address(peer_network, family)) is not None):
                        result.setdefault(router, set()).add(peer_address)
                        break
                else:
                    raise ConfigError(
                        f"{network}: {router} and {peer} have no common explicit IP address family",
                    )
    if not result:
        raise ConfigError("no inter-AS border-router links were found in gen/scion-dc.yml")
    return {router: sorted(peers) for router, peers in sorted(result.items())}


def tc_helper_name(router: str) -> str:
    return TC_HELPER_PREFIX + router.replace("-", "_")


def patch_compose(compose: dict[str, Any], peers: dict[str, list[str]], tc: dict[str, str]) -> None:
    """Add one profiled, network-namespace-sharing tc helper per border router."""
    services = compose["services"]
    for name in [name for name in services if name == "hummbwtester_tc_setup"
                 or name.startswith(TC_HELPER_PREFIX)]:
        del services[name]
    for router, peer_addresses in peers.items():
        # Each privileged, one-shot helper shares exactly one BR network namespace. The router
        # image itself stays unprivileged and does not need to contain iproute2.
        services[tc_helper_name(router)] = {
            "profiles": ["hummbwtester-setup"],
            "image": "scion/tester:latest",
            "user": "0:0",
            "cap_add": ["NET_ADMIN"],
            "network_mode": f"service:{router}",
            "depends_on": [router],
            "volumes": [{
                "type": "bind", "source": str(TC_SCRIPT),
                "target": "/share/hummbwtester_tc_setup.sh", "read_only": True,
            }],
            "entrypoint": ["/bin/bash", "/share/hummbwtester_tc_setup.sh"],
            "command": ["setup", tc["rate"], tc["burst"], tc["limit"], *peer_addresses],
        }
    COMPOSE.write_text(yaml.safe_dump(compose, sort_keys=False))


def run(command: list[str], *, check: bool = True, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Print and run a command, forwarding subprocess keyword arguments to subprocess.run."""
    # Print shell-escaped commands so setup failures can be reproduced manually.
    print("+", shlex.join(command))
    return subprocess.run(command, check=check, text=True, **kwargs)


def dc_args(*args: str) -> list[str]:
    """Build a Docker Compose command targeting the generated SCION Compose file."""
    return ["docker", "compose", "-f", str(COMPOSE), *args]


def require_built_binary() -> None:
    """Ensure `make build-dev` has produced the standard hummbwtester artifact."""
    if not BIN.is_file():
        raise RuntimeError(
            f"{BIN} does not exist; run `make build-dev` before setting up hummbwtester",
        )


def wait_for_reachability(server: Endpoint, client: Client, timeout: float = 60) -> None:
    """Poll SCION ping from client until it can reach server or timeout expires."""
    # scion ping takes a SCION host address, not the UDP endpoint used by hummbwtester.
    destination = f"{server.isd_as},{server.host}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = run(dc_args("exec", "-T", tester_service(client.endpoint.isd_as),
                             "scion", "ping", "-c", "1", destination), check=False,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError(f"timed out waiting for {client.client_id} to reach {destination}")


def write_targets(compose: dict[str, Any], clients: list[Client]) -> None:
    """Write Prometheus file-SD target files for client and border-router metrics."""
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    # client_id is the only custom Prometheus label for client metrics.
    client_targets = [{
        "targets": [join_host_port(client.endpoint.host, client.metrics_port)],
        "labels": {"client_id": client.client_id},
    } for client in clients]
    (TARGET_DIR / "clients.json").write_text(json.dumps(client_targets, indent=2) + "\n")

    ia_by_br = br_ias()
    targets = []
    for service, ia in sorted(ia_by_br.items()):
        # The BR's internal address is its second generated network address. Read topology instead
        # of relying on Compose network ordering.
        for topology in GEN.glob("AS*/topology.json"):
            data = json.loads(topology.read_text())
            if service in data.get("border_routers", {}):
                internal = data["border_routers"][service]["internal_addr"]
                host = internal.rsplit(":", 1)[0].strip("[]")
                targets.append({"targets": [join_host_port(host, 30442)],
                                "labels": {"as": ia.split("-", 1)[1].replace(":", "_"), "br": service}})
                break
    (TARGET_DIR / "border_routers.json").write_text(json.dumps(targets, indent=2) + "\n")


def setup(config_path: Path) -> int:
    """Build, start, shape, populate, and publish targets for one configured experiment."""
    server, clients, router, tc = load_config(config_path)
    compose = compose_data()
    validate_endpoints(compose, server, clients)
    _ = [endpoint_sciond(endpoint, sciond_map()) for endpoint in [server, *(c.endpoint for c in clients)]]
    peers = inter_as_router_peers(compose)
    # `make build-dev` builds this Bazel target as a static binary and extracts it into bin/.
    # Reusing that artifact keeps this tool consistent with the other tester-container binaries.
    require_built_binary()
    patch_router_configs(router)
    patch_compose(compose, peers, tc)
    # This is safe after `scion.sh stop`: Compose recreates the removed bridges before tc runs.
    run([str(ROOT / "scion.sh"), "start"], cwd=ROOT)
    wait_for_reachability(server, clients[0])
    for router_service in peers:
        run(dc_args("run", "--rm", "--no-deps", tc_helper_name(router_service)), cwd=ROOT)
    for client in clients:
        print(f"client_id={client.client_id} metrics_port={client.metrics_port}")
    for service in sorted({tester_service(server.isd_as), *(tester_service(c.endpoint.isd_as) for c in clients)}):
        run(dc_args("cp", str(BIN), f"{service}:/share/bin/hummbwtester"), cwd=ROOT)
        run(dc_args("exec", "-T", service, "test", "-x", "/share/bin/hummbwtester"), cwd=ROOT)
    write_targets(compose, clients)
    return 0


def verify_binaries(server: Endpoint, clients: list[Client]) -> None:
    """Check that setup copied a runnable hummbwtester binary to every needed tester."""
    # The runner deliberately does not rebuild; setup is responsible for placing this binary.
    services = {tester_service(server.isd_as)}
    services.update(tester_service(client.endpoint.isd_as) for client in clients)
    for service in sorted(services):
        run(dc_args("exec", "-T", service, "test", "-x", "/share/bin/hummbwtester"), cwd=ROOT)


def launch(
    service: str, pidfile: str, args: list[str], logfile: Path, marketplace_jwt_file: str | None = None,
) -> subprocess.Popen[str]:
    """Start one tester process through Compose and record its in-container PID and output."""
    logfile.parent.mkdir(parents=True, exist_ok=True)
    # The shell PID becomes the tester PID after exec. Saving it lets cleanup target exactly this
    # experiment process instead of broadly killing every hummbwtester in the shared container.
    command = "echo $$ > " + shlex.quote(pidfile) + "; "
    if marketplace_jwt_file is not None:
        # The token is read by the shell inside the container. The Compose invocation and this
        # command contain only its fixed path, never the JWT itself.
        command += "export SCION_MARKETPLACE_JWT=$(cat " + shlex.quote(marketplace_jwt_file) + "); "
    command += "exec " + shlex.join(args)
    print(f"logging {service} to {logfile}")
    compose_args = dc_args("exec", "-T")
    compose_args.extend([service, "/bin/bash", "-c", command])
    return subprocess.Popen(compose_args, cwd=ROOT,
                            stdout=logfile.open("w"), stderr=subprocess.STDOUT, text=True)


def stop_remote(service: str, pidfile: str) -> None:
    """Send SIGTERM to the process identified by pidfile in a tester container, if present."""
    # A missing pidfile means the process never launched or has already completed; that is harmless.
    run(dc_args("exec", "-T", service, "/bin/bash", "-c",
                f"test ! -f {shlex.quote(pidfile)} || kill -TERM $(cat {shlex.quote(pidfile)})"),
        cwd=ROOT, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def server_args(server: Endpoint, sciond: str) -> list[str]:
    """Build the hummbwtester command-line arguments for the configured server."""
    return [
        "/share/bin/hummbwtester", "-mode", "server", "-local", server.local(),
        "-sciond", sciond, "-receive-buffer-size", str(server.receive_buffer_size),
    ]


def client_args(client: Client, server: Endpoint, sciond: str) -> list[str]:
    """Build the hummbwtester command-line arguments for one configured client."""
    args = ["/share/bin/hummbwtester", "-mode", "client", "-local", client.endpoint.local(),
            "-remote", server.local(), "-sciond", sciond,
            "-bandwidth", client.bandwidth, "-maxburst", client.maxburst,
            "-duration", client.duration,
            "-metrics-addr", f":{client.metrics_port}"]
    if client.payload_size is not None:
        args.extend(["-payload-size", str(client.payload_size)])
    if client.pong_rate is not None:
        args.extend(["-pong-rate", str(client.pong_rate)])
    if client.hummingbird:
        assert client.hummingbird_reservation is not None
        reservation = client.hummingbird_reservation
        args.extend(["-hummingbird",
                     f"{reservation.bandwidth},{reservation.duration},{reservation.reverse_bandwidth}",
                     ])
        if client.reservation_source == "keys":
            args.extend(["-hummKeysDir", "/share/gen"])
        for flag, value in (
                ("-renewal-ahead", reservation.renewal_ahead),
                ("-reservation-overlap", reservation.reservation_overlap),
                ("-humm-start-offset", reservation.humm_start_offset)):
            if value is not None:
                args.extend([flag, value])
    return args


def marketplace_registration_website() -> str:
    """Find the unique TCP registration website advertised by the generated Docker topology."""
    websites: set[str] = set()
    for path in sorted(GEN.glob("AS*/staticInfoConfig.json")):
        try:
            static_info = json.loads(path.read_text())
            note = json.loads(static_info.get("note", "{}"))
        except (OSError, json.JSONDecodeError, AttributeError) as err:
            raise ConfigError(f"reading marketplace advertisement {path}: {err}") from err
        if not isinstance(note, dict):
            raise ConfigError(f"marketplace advertisement {path} is not an object")
        entries = note.get("hummingbird", [])
        if not isinstance(entries, list):
            raise ConfigError(f"marketplace advertisement {path} has invalid hummingbird entries")
        for entry in entries:
            if not isinstance(entry, dict) or "TLS/TCP" not in str(entry.get("api_protocol", "")):
                continue
            website = entry.get("client_registration_website") or entry.get("website")
            if isinstance(website, str) and website:
                websites.add(website)
    if not websites:
        raise ConfigError("no marketplace registration website advertised in gen/AS*/staticInfoConfig.json")
    if len(websites) != 1:
        raise ConfigError("multiple marketplace registration websites advertised: " +
                          ", ".join(sorted(websites)))
    return next(iter(websites))


def obtain_marketplace_jwt(marketplace: MarketplaceConfig) -> str:
    """Request the configured user's JWT without exposing its password or token in argv."""
    if not os.environ.get(marketplace.password_env):
        raise ConfigError(
            f"marketplace password environment variable {marketplace.password_env} is not set")
    command = [sys.executable, str(ROOT / "marketplace" / "tools" / "get_jwt.py"),
               marketplace.username, "--url", marketplace.url,
               "--password-env", marketplace.password_env]
    if marketplace.sub_account is not None:
        command.extend(["--sub-account", marketplace.sub_account])
    result = subprocess.run(
        command,
        cwd=ROOT, check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise ConfigError(f"marketplace login failed at {marketplace.url}: {result.stderr.strip()}")
    token = result.stdout.strip()
    if not token:
        raise ConfigError("marketplace login returned an empty JWT")
    return token


def write_private_jwt(token: str) -> Path:
    """Write token to an owner-only temporary file and return its path."""
    fd, name = tempfile.mkstemp(prefix="hummbwtester-jwt-", text=True)
    path = Path(name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as file:
            file.write(token)
            file.write("\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return path


def install_docker_jwt(token: str, services: set[str]) -> tuple[Path, str]:
    """Copy a private JWT file to selected containers and return local/remote paths."""
    local = write_private_jwt(token)
    remote = "/tmp/hummbwtester-marketplace.jwt"
    try:
        for service in sorted(services):
            run(dc_args("cp", str(local), f"{service}:{remote}"), cwd=ROOT)
            run(dc_args("exec", "-T", service, "chmod", "600", remote), cwd=ROOT)
    except BaseException:
        local.unlink(missing_ok=True)
        raise
    return local, remote


def remove_docker_jwt(services: set[str], remote: str) -> None:
    """Best-effort removal of an experiment's JWT from its containers."""
    for service in sorted(services):
        run(dc_args("exec", "-T", service, "rm", "-f", remote), cwd=ROOT,
            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def metric_samples(body: str, metric: str) -> dict[str, float]:
    """Return all labeled samples for metric from one Prometheus text exposition body."""
    samples: dict[str, float] = {}
    prefix = f"{metric}{{"
    for line in body.splitlines():
        if not line.startswith(prefix):
            continue
        labels_end = line.find("}")
        if labels_end == -1:
            raise RuntimeError(f"malformed {metric} sample: {line}")
        try:
            value = float(line[labels_end + 1:].strip().split()[0])
        except (IndexError, ValueError) as err:
            raise RuntimeError(f"malformed {metric} sample: {line}") from err
        samples[line[len(metric):labels_end + 1]] = value
    return samples


def metric_labels(rendered: str) -> dict[str, str]:
    """Parse the label fragment returned by metric_samples."""
    return {key: value for key, value in PROMETHEUS_LABEL_RE.findall(rendered)}


def address_host(address: str) -> str:
    """Return the host portion of a generated underlay address."""
    return address.rsplit(":", 1)[0].strip("[]")


def router_interfaces() -> list[RouterInterface]:
    """Return generated external interfaces, including their local and remote underlay addresses."""
    result: list[RouterInterface] = []
    for topology in GEN.glob("AS*/topology.json"):
        data = json.loads(topology.read_text())
        for router, entry in data.get("border_routers", {}).items():
            for interface, link in entry.get("interfaces", {}).items():
                underlay = link["underlay"]
                result.append(RouterInterface(
                    router=router,
                    isd_as=data["isd_as"],
                    interface=interface,
                    neighbor_isd_as=link["isd_as"],
                    local=address_host(underlay["local"]),
                    remote=address_host(underlay["remote"]),
                ))
    return sorted(result, key=lambda item: item.label)


def router_metric_endpoints() -> list[tuple[str, str]]:
    """Return one direct Prometheus endpoint for every generated border router."""
    result: list[tuple[str, str]] = []
    for topology in GEN.glob("AS*/topology.json"):
        data = json.loads(topology.read_text())
        for router, entry in data.get("border_routers", {}).items():
            result.append((router, f"http://{join_host_port(address_host(entry['internal_addr']), 30442)}/metrics"))
    return sorted(result)


def router_metric_bodies() -> tuple[dict[str, str], list[str]]:
    """Read router metrics without letting an unavailable observation endpoint stop the experiment."""
    bodies: dict[str, str] = {}
    errors: list[str] = []
    for router, url in router_metric_endpoints():
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                bodies[router] = response.read().decode()
        except OSError as err:
            errors.append(f"{router} metrics unavailable: {err}")
    return bodies, errors


def interface_counters(
    interfaces: list[RouterInterface],
    metric_bodies: dict[str, str],
) -> dict[tuple[str, str], InterfaceCounters]:
    """Collect cumulative BFD, demotion, and busy-forwarder counters per external interface."""
    values: dict[tuple[str, str], list[int]] = {
        interface.key: [0, 0, 0, 0]
        for interface in interfaces
        if interface.router in metric_bodies
    }
    demotion_metrics = (
        "router_humm_demoted_freshness_total",
        "router_humm_demoted_expired_total",
        "router_humm_demoted_tokenbucket_total",
    )
    for router, body in metric_bodies.items():
        for metric, index in (
            ("router_bfd_sent_packets_total", 0),
            ("router_bfd_received_packets_total", 1),
        ):
            for rendered, value in metric_samples(body, metric).items():
                labels = metric_labels(rendered)
                key = router, labels.get("interface", "")
                if key in values:
                    values[key][index] += int(value)
        for metric in demotion_metrics:
            for rendered, value in metric_samples(body, metric).items():
                labels = metric_labels(rendered)
                key = router, labels.get("interface", "")
                if key in values:
                    values[key][2] += int(value)
        for rendered, value in metric_samples(body, "router_dropped_pkts_total").items():
            labels = metric_labels(rendered)
            key = router, labels.get("interface", "")
            if key in values and labels.get("reason") == "busy_forwarder":
                values[key][3] += int(value)
    return {
        key: InterfaceCounters(*counters)
        for key, counters in values.items()
    }


def tc_stats(compose: dict[str, Any], interfaces: list[RouterInterface]) -> tuple[dict[tuple[str, str], TCStats], list[str]]:
    """Read TBF counters without draining queues or treating counter values as failures."""
    remote_interfaces = {interface.remote: interface.key for interface in interfaces}
    stats: dict[tuple[str, str], TCStats] = {}
    errors: list[str] = []
    helpers = sorted(name for name in compose["services"] if name.startswith(TC_HELPER_PREFIX))
    for helper in helpers:
        service = compose["services"][helper]
        command = service.get("command", [])
        peers = command[4:] if len(command) >= 5 and command[0] == "setup" else []
        if not peers:
            errors.append(f"{helper} has no configured peers")
            continue
        result = subprocess.run(
            dc_args("run", "--rm", "--no-deps", helper, "stats", *peers),
            cwd=ROOT,
            check=False,
            text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            errors.append(f"{helper} tc stats failed: {result.stderr.strip() or result.stdout.strip()}")
            continue
        for line in result.stdout.splitlines():
            match = TC_STATS_RE.fullmatch(line)
            if match is None:
                continue
            peer, _, dropped, overlimits, backlog = match.groups()
            if (key := remote_interfaces.get(peer)) is None:
                errors.append(f"{helper} reported unknown tc peer {peer}")
                continue
            stats[key] = TCStats(int(dropped), int(overlimits), int(backlog))
    return stats, errors


def report_snapshot(compose: dict[str, Any], interfaces: list[RouterInterface]) -> ReportSnapshot:
    """Capture all observability data; failures are rendered in the report and never abort traffic."""
    bodies, metric_errors = router_metric_bodies()
    tc, tc_errors = tc_stats(compose, interfaces)
    return ReportSnapshot(interface_counters(interfaces, bodies), tc, tuple(metric_errors + tc_errors))


def counter_delta(previous: int | None, current: int | None) -> str:
    """Render a non-negative counter change, or an unavailable value."""
    if previous is None or current is None:
        return "-"
    return str(max(0, current - previous))


def peer_interfaces(interfaces: list[RouterInterface]) -> dict[tuple[str, str], tuple[str, str]]:
    """Map each interface to the peer interface with swapped underlay endpoints."""
    result: dict[tuple[str, str], tuple[str, str]] = {}
    for interface in interfaces:
        for peer in interfaces:
            if interface.local == peer.remote and interface.remote == peer.local:
                result[interface.key] = peer.key
                break
    return result


def render_table(headers: list[str], rows: list[tuple[str, list[str]]]) -> str:
    """Render a compact ASCII table without adding a third-party reporting dependency."""
    widths = [len(headers[0]), *(len(header) for header in headers[1:])]
    for name, values in rows:
        widths[0] = max(widths[0], len(name))
        for index, value in enumerate(values, start=1):
            widths[index] = max(widths[index], len(value))
    def line(values: list[str]) -> str:
        return " | ".join(value.rjust(widths[index]) for index, value in enumerate(values))
    divider = "-+-".join("-" * width for width in widths)
    return "\n".join([line(headers), divider, *(line([name, *values]) for name, values in rows)])


def print_report(previous: ReportSnapshot, current: ReportSnapshot, interfaces: list[RouterInterface]) -> None:
    """Print one minute of router and TBF observations without enforcing a health policy."""
    peers = peer_interfaces(interfaces)
    def counters(snapshot: ReportSnapshot, interface: RouterInterface) -> InterfaceCounters | None:
        return snapshot.counters.get(interface.key)
    def tc(snapshot: ReportSnapshot, interface: RouterInterface) -> TCStats | None:
        return snapshot.tc.get(interface.key)
    def bfd_lost(interface: RouterInterface) -> str:
        local_previous, local_current = counters(previous, interface), counters(current, interface)
        peer = peers.get(interface.key)
        peer_previous = previous.counters.get(peer) if peer else None
        peer_current = current.counters.get(peer) if peer else None
        if None in (local_previous, local_current, peer_previous, peer_current):
            return "-"
        assert local_previous and local_current and peer_previous and peer_current
        sent = peer_current.bfd_sent - peer_previous.bfd_sent
        received = local_current.bfd_received - local_previous.bfd_received
        return str(max(0, sent - received))
    def counter_row(field: str) -> list[str]:
        return [counter_delta(
            getattr(counters(previous, interface), field) if counters(previous, interface) else None,
            getattr(counters(current, interface), field) if counters(current, interface) else None,
        ) for interface in interfaces]
    def tc_row(field: str, current_value: bool = False) -> list[str]:
        values: list[str] = []
        for interface in interfaces:
            before, after = tc(previous, interface), tc(current, interface)
            if current_value:
                values.append(str(getattr(after, field)) if after else "-")
            else:
                values.append(counter_delta(
                    getattr(before, field) if before else None,
                    getattr(after, field) if after else None,
                ))
        return values
    rows = [
        # ("BFD sent", counter_row("bfd_sent")),
        # ("BFD received", counter_row("bfd_received")),
        # ("BFD lost", [bfd_lost(interface) for interface in interfaces]),
        # ("Demotions", counter_row("demotions")),
        # ("Busy forwarder drops", counter_row("busy_forwarder_drops")),
        ("TC dropped", tc_row("dropped")),
        # ("TC overlimits", tc_row("overlimits")),
        # ("TC backlog bytes", tc_row("backlog_bytes", current_value=True)),
    ]
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    print(f"{timestamp} HUMMBWTESTER_REPORT interval=60s (counters are deltas; TC backlog is current)")
    print(render_table(["metric", *(interface.label for interface in interfaces)], rows))
    print()
    for error in current.errors:
        print(f"HUMMBWTESTER_REPORT observation_error={error}")


def run_experiment(config_path: Path) -> int:
    """Launch the server and all clients, then return their aggregate experiment status."""
    server, clients, _, _ = load_config(config_path)
    compose = compose_data()
    validate_endpoints(compose, server, clients)
    daemons = sciond_map()
    verify_binaries(server, clients)
    # Regenerate targets here too, so editing client IDs does not require a separate monitoring step.
    write_targets(compose, clients)
    server_service = tester_service(server.isd_as)
    log_dir = ROOT / "logs" / "hummbwtester"
    server_pidfile = "/tmp/hummbwtester-server.pid"
    args = server_args(server, endpoint_sciond(server, daemons))
    processes: list[tuple[Client, str, subprocess.Popen[str]]] = []
    interfaces = router_interfaces()
    marketplace_jwt_file: Path | None = None
    remote_jwt_file: str | None = None
    marketplace_services: set[str] = set()
    hummingbird_clients = [client for client in clients if client.hummingbird]
    server_process: subprocess.Popen[str] | None = None
    try:
        if hummingbird_clients and hummingbird_clients[0].reservation_source == "marketplace":
            client = hummingbird_clients[0]
            assert client.marketplace is not None
            marketplace_services = {tester_service(client.endpoint.isd_as) for client in hummingbird_clients}
            # A Docker topology advertises the registration endpoint that is actually reachable
            # from this controller. The workload URL is for the SSH backend, where gen/ is absent.
            marketplace = replace(client.marketplace, url=marketplace_registration_website())
            marketplace_jwt_file, remote_jwt_file = install_docker_jwt(
                obtain_marketplace_jwt(marketplace), marketplace_services)
        server_process = launch(server_service, server_pidfile, args, log_dir / "server.log")
        # Give the server a predictable head start before clients begin selecting paths and dialing.
        time.sleep(2)
        for client in clients:
            suffix = client.client_id
            args = client_args(client, server, endpoint_sciond(client.endpoint, daemons))
            pidfile = f"/tmp/hummbwtester-{suffix}.pid"
            jwt_file = remote_jwt_file if client.hummingbird else None
            processes.append((client, pidfile, launch(tester_service(client.endpoint.isd_as), pidfile, args,
                                                       log_dir / f"{suffix}.log", jwt_file)))
        failure = False
        previous_report = report_snapshot(compose, interfaces)
        next_report = time.monotonic() + 60
        # A prematurely exited server invalidates the experiment even if clients are still alive.
        while any(process.poll() is None for _, _, process in processes):
            if server_process.poll() is not None:
                failure = True
                break
            if time.monotonic() >= next_report:
                current_report = report_snapshot(compose, interfaces)
                print_report(previous_report, current_report, interfaces)
                previous_report = current_report
                next_report += 60
            time.sleep(0.25)
        failure = failure or any(process.wait() != 0 for _, _, process in processes)
        return 1 if failure else 0
    except KeyboardInterrupt:
        return 130
    finally:
        # Always remove the server and any remaining clients on failure or Ctrl-C.
        for client, pidfile, process in processes:
            # Ctrl-C can terminate the local ``docker compose exec`` wrapper before it reaches
            # the tester process in the container. The pidfile is the authoritative record of
            # that process, so always target it even when the local wrapper has already exited.
            stop_remote(tester_service(client.endpoint.isd_as), pidfile)
            if process.poll() is None:
                process.terminate()
        stop_remote(server_service, server_pidfile)
        if server_process is not None and server_process.poll() is None:
            server_process.terminate()
        for _, _, process in processes:
            process.wait(timeout=10)
        if server_process is not None:
            server_process.wait(timeout=10)
        if remote_jwt_file is not None:
            remove_docker_jwt(marketplace_services, remote_jwt_file)
        if marketplace_jwt_file is not None:
            marketplace_jwt_file.unlink(missing_ok=True)


def main(default_mode: str | None = None) -> int:
    """Parse CLI arguments and dispatch to setup or run, optionally forcing the mode."""
    # The two small entrypoint scripts pass "setup" or "run" directly. Running this module
    # itself leaves the mode as None, so argparse requires the user to choose one.
    parser = argparse.ArgumentParser()
    if default_mode is None:
        parser.add_argument("mode", choices=("setup", "run"))
    parser.add_argument("--config", type=Path, default=CONFIG_DEFAULT)
    args = parser.parse_args()
    try:
        mode = default_mode if default_mode is not None else args.mode
        return setup(args.config) if mode == "setup" else run_experiment(args.config)
    except (ConfigError, RuntimeError, subprocess.SubprocessError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
