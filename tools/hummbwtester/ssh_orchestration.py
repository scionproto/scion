#!/usr/bin/env python3
"""Run hummbwtester on explicitly inventoried SSH-accessible SCION hosts.

This module deliberately knows nothing about generated Docker topology. The workload stays in
hummbwtester.json; ssh-inventory.json says exactly where each workload participant runs.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
import uuid
from typing import Any

try:  # Support both ``python -m``/tests and the small direct entrypoint script.
    from . import orchestration as workload
except ImportError:
    import orchestration as workload


ROOT = workload.ROOT
BIN = workload.BIN
TC_HELPER = ROOT / "tools" / "hummbwtester" / "tc_remote.sh"
INVENTORY_DEFAULT = ROOT / "tools" / "hummbwtester" / "ssh-inventory.json"
TARGET_DIR = workload.TARGET_DIR


@dataclass(frozen=True)
class SSHHost:
    name: str
    alias: str
    sciond: str
    run_dir: str
    readiness_command: str | None


@dataclass(frozen=True)
class RouterMetrics:
    host: str
    address: str
    labels: dict[str, str]


@dataclass(frozen=True)
class ShapedInterface:
    host: str
    device: str
    baseline: str


@dataclass(frozen=True)
class Inventory:
    hosts: dict[str, SSHHost]
    server_host: str
    client_hosts: dict[str, str]
    local_port_base: int
    routers: tuple[RouterMetrics, ...]
    shaping: tuple[ShapedInterface, ...]


class SSHError(RuntimeError):
    pass


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise workload.ConfigError(f"{context} must be an object")
    return value


def _fields(value: dict[str, Any], required: set[str], context: str, optional: set[str] = set()) -> None:
    workload.require_fields(value, required, context, optional)


def _name(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or any(char.isspace() for char in value):
        raise workload.ConfigError(f"{context} must be a non-empty string without whitespace")
    return value


def _host_port(value: str, context: str) -> tuple[str, str]:
    """Parse the host:port form used for the daemon and tunneled TCP endpoints."""
    host, separator, port = value.rpartition(":")
    if not separator or not host or not port.isdecimal() or not 1 <= int(port) <= 65535:
        raise workload.ConfigError(f"{context} must be a host:port endpoint")
    return host.strip("[]"), port


def load_inventory(path: Path, clients: list[workload.Client]) -> Inventory:
    """Read an explicit, closed SSH inventory and validate its workload placements."""
    root = workload.read_json(path)
    _fields(root, {"hosts", "placements", "metrics", "shaping"}, "ssh inventory")
    raw_hosts = _object(root["hosts"], "ssh inventory.hosts")
    if not raw_hosts:
        raise workload.ConfigError("ssh inventory.hosts must not be empty")
    hosts: dict[str, SSHHost] = {}
    for name, raw in raw_hosts.items():
        name = _name(name, "ssh inventory host name")
        entry = _object(raw, f"ssh inventory.hosts.{name}")
        _fields(entry, {"ssh", "sciond", "run_dir"}, f"ssh inventory.hosts.{name}",
                {"readiness_command"})
        run_dir = _name(entry["run_dir"], f"ssh inventory.hosts.{name}.run_dir")
        if not run_dir.startswith("/"):
            raise workload.ConfigError(f"ssh inventory.hosts.{name}.run_dir must be absolute")
        readiness = entry.get("readiness_command")
        if readiness is not None and (not isinstance(readiness, str) or not readiness):
            raise workload.ConfigError(f"ssh inventory.hosts.{name}.readiness_command must be a string")
        sciond = _name(entry["sciond"], f"ssh inventory.hosts.{name}.sciond")
        _host_port(sciond, f"ssh inventory.hosts.{name}.sciond")
        hosts[name] = SSHHost(name, _name(entry["ssh"], f"ssh inventory.hosts.{name}.ssh"), sciond,
                              run_dir, readiness)

    placements = _object(root["placements"], "ssh inventory.placements")
    _fields(placements, {"server", "clients"}, "ssh inventory.placements")
    server_host = _name(placements["server"], "ssh inventory.placements.server")
    raw_clients = _object(placements["clients"], "ssh inventory.placements.clients")
    client_hosts = {str(client_id): _name(host, f"ssh inventory placement for {client_id}")
                    for client_id, host in raw_clients.items()}
    expected = {client.client_id for client in clients}
    if set(client_hosts) != expected:
        raise workload.ConfigError("ssh inventory client placements must match workload client_id values")
    for host in [server_host, *client_hosts.values()]:
        if host not in hosts:
            raise workload.ConfigError(f"ssh inventory placement references unknown host {host}")

    metrics = _object(root["metrics"], "ssh inventory.metrics")
    _fields(metrics, {"local_port_base", "routers"}, "ssh inventory.metrics")
    base = metrics["local_port_base"]
    if not isinstance(base, int) or isinstance(base, bool) or not 1024 <= base <= 65000:
        raise workload.ConfigError("ssh inventory.metrics.local_port_base must be an integer from 1024 through 65000")
    raw_routers = metrics["routers"]
    if not isinstance(raw_routers, list):
        raise workload.ConfigError("ssh inventory.metrics.routers must be an array")
    routers: list[RouterMetrics] = []
    for index, raw in enumerate(raw_routers):
        entry = _object(raw, f"ssh inventory.metrics.routers[{index}]")
        _fields(entry, {"host", "address", "labels"}, f"ssh inventory.metrics.routers[{index}]")
        host, address = (_name(entry["host"], f"ssh inventory.metrics.routers[{index}].host"),
                         _name(entry["address"], f"ssh inventory.metrics.routers[{index}].address"))
        if host not in hosts:
            raise workload.ConfigError(f"ssh inventory.metrics.routers[{index}] has an unknown host or invalid address")
        _host_port(address, f"ssh inventory.metrics.routers[{index}].address")
        labels = _object(entry["labels"], f"ssh inventory.metrics.routers[{index}].labels")
        if not all(isinstance(key, str) and isinstance(value, str) for key, value in labels.items()):
            raise workload.ConfigError(f"ssh inventory.metrics.routers[{index}].labels must be string pairs")
        routers.append(RouterMetrics(host, address, labels))

    raw_shaping = root["shaping"]
    if not isinstance(raw_shaping, list):
        raise workload.ConfigError("ssh inventory.shaping must be an array")
    shaping: list[ShapedInterface] = []
    seen: set[tuple[str, str]] = set()
    for index, raw in enumerate(raw_shaping):
        entry = _object(raw, f"ssh inventory.shaping[{index}]")
        _fields(entry, {"host", "device", "baseline"}, f"ssh inventory.shaping[{index}]")
        shape = ShapedInterface(_name(entry["host"], f"ssh inventory.shaping[{index}].host"),
                                _name(entry["device"], f"ssh inventory.shaping[{index}].device"),
                                _name(entry["baseline"], f"ssh inventory.shaping[{index}].baseline"))
        if shape.host not in hosts or shape.baseline != "noqueue" or (shape.host, shape.device) in seen:
            raise workload.ConfigError(f"ssh inventory.shaping[{index}] must name a unique host device with baseline noqueue")
        seen.add((shape.host, shape.device))
        shaping.append(shape)
    return Inventory(hosts, server_host, client_hosts, base, tuple(routers), tuple(shaping))


def ssh_command(host: SSHHost, command: str, *, check: bool = True, **kwargs: Any) -> subprocess.CompletedProcess[str]:
    """Run an already quoted, non-secret command through the configured SSH alias."""
    return subprocess.run(["ssh", "--", host.alias, "sh", "-c", command], check=check,
                          text=True, **kwargs)


def scp_to(host: SSHHost, local: Path, remote: str) -> None:
    subprocess.run(["scp", str(local), f"{host.alias}:{remote}"], check=True, text=True)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def remote_dir(host: SSHHost, run_id: str) -> str:
    return f"{host.run_dir}/{run_id}"


def preflight(host: SSHHost) -> None:
    daemon_host, daemon_port = _host_port(host.sciond, f"SSH host {host.name} sciond")
    command = " && ".join([
        "command -v sha256sum >/dev/null",
        "command -v nc >/dev/null",
        f"install -d -m 700 {shlex.quote(host.run_dir)}",
        f"nc -z -w 3 {shlex.quote(daemon_host)} {shlex.quote(daemon_port)}",
        host.readiness_command or "true",
    ])
    ssh_command(host, command)


def deploy(host: SSHHost, run_id: str, digest: str, need_tc: bool) -> None:
    directory = remote_dir(host, run_id)
    ssh_command(host, f"install -d -m 700 {shlex.quote(directory)}")
    scp_to(host, BIN, f"{directory}/hummbwtester")
    if need_tc:
        scp_to(host, TC_HELPER, f"{directory}/tc_remote.sh")
    command = (
        f"test \"$(sha256sum {shlex.quote(directory + '/hummbwtester')} | awk '{{print $1}}')\" = {shlex.quote(digest)}"
        f" && chmod 700 {shlex.quote(directory + '/hummbwtester')}"
    )
    if need_tc:
        command += f" && chmod 700 {shlex.quote(directory + '/tc_remote.sh')}"
    ssh_command(host, command)


def upload_jwt(host: SSHHost, run_id: str, local_jwt: Path) -> str:
    target = remote_dir(host, run_id) + "/marketplace.jwt"
    scp_to(host, local_jwt, target)
    ssh_command(host, f"chmod 600 {shlex.quote(target)}")
    return target


def launch(host: SSHHost, run_id: str, name: str, args: list[str], logfile: Path,
           jwt_file: str | None = None) -> subprocess.Popen[str]:
    """Launch a tester tied to its SSH session and retain a remote PID for cleanup."""
    logfile.parent.mkdir(parents=True, exist_ok=True)
    directory = remote_dir(host, run_id)
    args = [directory + "/hummbwtester", *args[1:]]
    command = f"echo $$ > {shlex.quote(directory + '/' + name + '.pid')}; "
    if jwt_file is not None:
        command += f"export SCION_MARKETPLACE_JWT=$(cat {shlex.quote(jwt_file)}); "
    command += "exec " + shlex.join(args)
    print(f"logging {name} on {host.name} to {logfile}")
    output = logfile.open("w")
    try:
        process = subprocess.Popen(["ssh", "--", host.alias, "sh", "-c", command], text=True,
                                   stdout=output, stderr=subprocess.STDOUT)
    finally:
        output.close()
    return process


def stop(host: SSHHost, run_id: str, name: str) -> None:
    pidfile = remote_dir(host, run_id) + "/" + name + ".pid"
    ssh_command(host, f"test ! -f {shlex.quote(pidfile)} || kill -TERM $(cat {shlex.quote(pidfile)})",
                check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def cleanup_host(host: SSHHost, run_id: str) -> None:
    ssh_command(host, f"rm -rf {shlex.quote(remote_dir(host, run_id))}", check=False,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def apply_shaping(inventory: Inventory, run_id: str, tc: dict[str, str]) -> list[ShapedInterface]:
    applied: list[ShapedInterface] = []
    for shape in inventory.shaping:
        host = inventory.hosts[shape.host]
        helper = remote_dir(host, run_id) + "/tc_remote.sh"
        ssh_command(host, "sudo -n " + shlex.join(
            [helper, "apply", shape.device, tc["rate"], tc["burst"], tc["limit"]]))
        applied.append(shape)
    return applied


def cleanup_shaping(inventory: Inventory, run_id: str, shapes: list[ShapedInterface]) -> None:
    for shape in shapes:
        host = inventory.hosts[shape.host]
        helper = remote_dir(host, run_id) + "/tc_remote.sh"
        ssh_command(host, "sudo -n " + shlex.join([helper, "cleanup", shape.device]), check=False)


def collect_shaping_stats(inventory: Inventory, run_id: str, shapes: list[ShapedInterface]) -> None:
    """Print the explicit dedicated-link qdisc counters without inspecting other interfaces."""
    for shape in shapes:
        host = inventory.hosts[shape.host]
        helper = remote_dir(host, run_id) + "/tc_remote.sh"
        result = ssh_command(host, "sudo -n " + shlex.join([helper, "stats", shape.device]),
                             check=False, capture_output=True)
        if result.returncode:
            print(f"HUMMBWTESTER_TC_STATS_ERROR host={host.name} dev={shape.device} "
                  f"error={result.stderr.strip()}", file=sys.stderr)
        else:
            print(f"host={host.name} {result.stdout.strip()}")


def start_tunnel(host: SSHHost, local_port: int, remote_address: str) -> subprocess.Popen[str]:
    return subprocess.Popen(["ssh", "-N", "-L", f"127.0.0.1:{local_port}:{remote_address}", "--", host.alias],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, text=True)


def write_targets(inventory: Inventory, clients: list[workload.Client]) -> list[subprocess.Popen[str]]:
    """Open controller-owned tunnels and publish the corresponding Prometheus file-SD files."""
    TARGET_DIR.mkdir(parents=True, exist_ok=True)
    tunnels: list[subprocess.Popen[str]] = []
    client_targets = []
    for index, client in enumerate(clients):
        port = inventory.local_port_base + index
        tunnels.append(start_tunnel(inventory.hosts[inventory.client_hosts[client.client_id]], port,
                                    f"127.0.0.1:{client.metrics_port}"))
        client_targets.append({"targets": [f"127.0.0.1:{port}"], "labels": {"client_id": client.client_id}})
    router_targets = []
    for index, router in enumerate(inventory.routers, start=len(clients)):
        port = inventory.local_port_base + index
        tunnels.append(start_tunnel(inventory.hosts[router.host], port, router.address))
        router_targets.append({"targets": [f"127.0.0.1:{port}"], "labels": router.labels})
    (TARGET_DIR / "clients.json").write_text(json.dumps(client_targets, indent=2) + "\n")
    (TARGET_DIR / "border_routers.json").write_text(json.dumps(router_targets, indent=2) + "\n")
    return tunnels


def run_experiment(config_path: Path, inventory_path: Path) -> int:
    workload.require_built_binary()
    server, clients, _, tc = workload.load_config(config_path)
    inventory = load_inventory(inventory_path, clients)
    if inventory.local_port_base + len(clients) + len(inventory.routers) > 65535:
        raise workload.ConfigError("SSH metrics tunnel ports exceed 65535")
    run_id = "hummbwtester-" + uuid.uuid4().hex[:12]
    used_hosts = {inventory.server_host, *inventory.client_hosts.values()}
    digest = sha256(BIN)
    local_jwt: Path | None = None
    processes: list[tuple[SSHHost, str, subprocess.Popen[str]]] = []
    tunnels: list[subprocess.Popen[str]] = []
    applied_shaping: list[ShapedInterface] = []
    try:
        for name in sorted(used_hosts):
            preflight(inventory.hosts[name])
            deploy(inventory.hosts[name], run_id, digest,
                   any(shape.host == name for shape in inventory.shaping))
        hummingbird_clients = [client for client in clients if client.hummingbird]
        jwt_files: dict[str, str] = {}
        if hummingbird_clients and hummingbird_clients[0].reservation_source == "marketplace":
            marketplace = hummingbird_clients[0].marketplace
            assert marketplace is not None
            local_jwt = workload.write_private_jwt(workload.obtain_marketplace_jwt(marketplace))
            for name in {inventory.client_hosts[client.client_id] for client in hummingbird_clients}:
                jwt_files[name] = upload_jwt(inventory.hosts[name], run_id, local_jwt)
        applied_shaping = apply_shaping(inventory, run_id, tc)
        collect_shaping_stats(inventory, run_id, applied_shaping)
        tunnels = write_targets(inventory, clients)
        server_host = inventory.hosts[inventory.server_host]
        processes.append((server_host, "server", launch(
            server_host, run_id, "server", workload.server_args(server, server_host.sciond),
            ROOT / "logs" / "hummbwtester" / "ssh-server.log")))
        time.sleep(2)
        for client in clients:
            host = inventory.hosts[inventory.client_hosts[client.client_id]]
            jwt_file = jwt_files.get(host.name) if client.hummingbird else None
            processes.append((host, client.client_id, launch(
                host, run_id, client.client_id, workload.client_args(client, server, host.sciond),
                ROOT / "logs" / "hummbwtester" / f"ssh-{client.client_id}.log", jwt_file)))
        failure = False
        next_stats = time.monotonic() + 60
        while any(process.poll() is None for _, _, process in processes[1:]):
            if processes[0][2].poll() is not None:
                failure = True
                break
            if time.monotonic() >= next_stats:
                collect_shaping_stats(inventory, run_id, applied_shaping)
                next_stats += 60
            time.sleep(0.25)
        return 1 if failure or any(process.wait() != 0 for _, _, process in processes) else 0
    except KeyboardInterrupt:
        return 130
    finally:
        for host, name, process in processes:
            stop(host, run_id, name)
            if process.poll() is None:
                process.terminate()
        for tunnel in tunnels:
            if tunnel.poll() is None:
                tunnel.terminate()
        for _, _, process in processes:
            process.wait(timeout=10)
        for tunnel in tunnels:
            tunnel.wait(timeout=10)
        if applied_shaping:
            collect_shaping_stats(inventory, run_id, applied_shaping)
            cleanup_shaping(inventory, run_id, applied_shaping)
        for name in used_hosts:
            cleanup_host(inventory.hosts[name], run_id)
        if local_jwt is not None:
            local_jwt.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=workload.CONFIG_DEFAULT)
    parser.add_argument("--inventory", type=Path, default=INVENTORY_DEFAULT)
    args = parser.parse_args()
    try:
        return run_experiment(args.config, args.inventory)
    except (workload.ConfigError, SSHError, subprocess.SubprocessError, RuntimeError) as err:
        print(f"error: {err}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
