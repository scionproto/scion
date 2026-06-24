# SCION containerlab node image — design

Status: partially implemented. Purpose: a stable reference (for humans and
future prompts) describing the SCION [containerlab](https://containerlab.dev/)
node image we are building. Everything described here lives under
`testing/clab/`.

Implemented so far: the Go controller (PID 1 init + supervisor; no config API
yet) and the `//testing/clab:clab_node` image. Still open: the configuration
API and the address/port plan generator (see [Open items](#open-items)).

## Target picture

One **containerlab node = one ISD-AS**, packaged as a single Docker/OCI image
that contains:

- a **Go controller** that runs as **PID 1** (init + process supervisor +
  configuration API);
- the SCION service binaries it manages — **router**, **control service**,
  **daemon** (`sciond`), and the **dispatcher**;
- the **`scion` CLI** for in-node debugging (`docker exec ... scion ping`, etc.).

The controller boots the AS's services, supervises them, and exposes an API that
lets us (re)configure the router, control, and daemon at runtime. Inter-AS links
are containerlab `links:` between AS nodes; everything inside an AS shares the
node's network namespace.

The image is **built with Bazel**, reusing the existing OCI image tooling
(`rules_oci`) and the SCION **tester image** (`//docker:tester`) as its base.

```text
                containerlab node (one ISD-AS)
   ┌─────────────────────────────────────────────────────┐
   │  PID 1: Go controller                                │
   │    ├─ config API (HTTP/gRPC)  ◄── operator / tests   │
   │    ├─ writes *.toml + topology.json into /etc/scion  │
   │    └─ supervises (start/stop/reap/signal):           │
   │         ├─ /app/dispatcher --config /etc/scion/disp_*.toml
   │         ├─ /app/router   --config /etc/scion/br*.toml│
   │         ├─ /app/control  --config /etc/scion/cs*.toml│
   │         └─ /app/daemon   --config /etc/scion/sd.toml │
   │  /app/scion  (CLI, on demand)                        │
   └─────────────────────────────────────────────────────┘
        │ veth (clab link)            │ veth (clab link)
        ▼                             ▼
     peer AS node                  peer AS node
```

## Layout under `testing/clab/`

- `testing/clab/controller/` — the Go controller (PID 1) source + `BUILD.bazel`
  (`//testing/clab/controller`).
- `testing/clab/BUILD.bazel` — the `oci_image`/`oci_load` targets for the node
  image (`//testing/clab:clab_node`).
- `testing/clab/` — example `*.clab.yml` topologies and any seed config.
- `testing/clab/README.md` — this document.

## The Go controller (PID 1)

A single static Go binary, image entrypoint. Responsibilities:

### Init duties

- **Reap zombies.** Orphaned grandchildren are reparented to PID 1, so the
  controller must `wait4(-1, …)` for *any* child, not only the ones it spawned.
- **Forward signals.** Translate `SIGTERM`/`SIGINT` (from `docker stop` /
  `clab destroy`) into a clean shutdown of all managed services, then exit.
- **Supervise.** Track `pid → service`, restart on crash with backoff (policy
  configurable per service), and surface state through the API/logs.

Implementation note: do **not** use `cmd.Wait()` per child alongside a central
`Wait4(-1)` reaper — they race and `cmd.Wait()` errors with
`waitid: no child process`. Spawn with `Start()`, record pids, and do all
reaping centrally in the `SIGCHLD` handler.

### Configuration API

The controller owns `/etc/scion` and is the only writer of service config. It
exposes an API (HTTP or gRPC — TBD) to:

- set/update the node's SCION configuration — the AS's `topology.json`, the
  per-service `*.toml`, keys/certs/TRCs;
- start/stop/restart individual services;
- query service + config status.

Apply model per service:

- **control** — rewrite `topology.json`; control reloads topology on **SIGHUP**
  (`app.SIGHUPChannel`, see
  [`control/cmd/control/main.go`](../../control/cmd/control/main.go)
  `topology.NewLoader{Reload: ...}`). Other config changes → restart.
- **daemon** — same: topology reloads on **SIGHUP**
  ([`daemon/cmd/daemon/main.go`](../../daemon/cmd/daemon/main.go)).
- **router** — loads config once at startup
  ([`router/cmd/router/main.go`](../../router/cmd/router/main.go)
  `loadControlConfig`); reconfigure = **restart** the router process.

So the controller's update flow is: write files → SIGHUP where supported, else
restart the affected service. This keeps the data-plane/control-plane code
unchanged and puts all orchestration logic in the controller.

### Shared network namespace

All services in the node share one netns, so their addresses in `topology.json`
must not collide on `host:port`. The controller is responsible for producing a
consistent address plan (distinct ports on the node IP, or extra addresses on
`lo` / the link interfaces). Multiple border routers in one AS are just multiple
`/app/router` processes, each binding its own link interface(s).

## Build (Bazel)

The node image is defined in [`testing/clab/BUILD.bazel`](BUILD.bazel) with
`oci_image`/`oci_load`/`pkg_tar` via `rules_oci`. It differs from the per-service
`scion_app_image` (one distroless binary per image) in three ways:

1. **Multi-binary**: package `//router/cmd/router`, `//control/cmd/control`,
   `//daemon/cmd/daemon`, `//dispatcher/cmd/dispatcher`, `//scion/cmd/scion`,
   and the controller binary into `/app`.
2. **Entrypoint is the controller**, not a service binary.
3. **Base with a shell + net tooling**: the SCION tester image
   ([`//docker:tester`](../../docker/tester.bzl)), a non-distroless Debian that
   already ships `bash`, `iproute2`, `iptables`, `tshark`, `iputils-ping`, etc.,
   so `docker exec`, the `scion` CLI, and `ip`/`tshark` debugging work inside lab
   nodes.

The node image target in `testing/clab/BUILD.bazel`:

```python
pkg_tar(
    name = "clab_node_bins",
    srcs = [
        "//control/cmd/control",
        "//daemon/cmd/daemon",
        "//dispatcher/cmd/dispatcher",
        "//router/cmd/router",
        "//scion/cmd/scion",
        "//testing/clab/controller",
    ],
    package_dir = "/app",
    mode = "0755",
)

oci_image(
    name = "clab_node",
    base = "//docker:tester",   # non-distroless; shell + net tooling
    entrypoint = ["/app/controller"],
    tars = [":clab_node_bins"],
    workdir = "/share",
)

oci_load(
    name = "clab_node.load",
    image = ":clab_node",
    repo_tags = ["scion/clab-node:latest"],
    format = "docker",
)
```

`bazel run //testing/clab:clab_node.load` loads the image into Docker for use by
containerlab. The controller binary lives at `testing/clab/controller` and builds
as a normal `scion_go_binary` (`//testing/clab/controller`).

## containerlab usage

Each AS is one node using the image; the controller starts the AS's services.
Configuration is supplied to the controller (mounted seed config and/or pushed
via the API). For a fast dev loop, bind-mount freshly built static binaries over
`/app` so iterating means rebuild + restart node, no image rebuild:

```yaml
topology:
  nodes:
    as110:
      kind: linux
      image: scion/clab-node:latest
      binds:
        - bin:/app:ro                       # optional: host-built binaries
        - gen/ASff00_0_110:/etc/scion:rw    # seed config (controller owns it)
  links:
    - endpoints: ["as110:eth1", "as120:eth1"]   # inter-AS link
```

## Open items

1. API surface + transport (HTTP vs gRPC) and config schema the controller
   accepts.
2. Address/port plan generator for co-located services in one netns (likely an
   adaptation of the existing `topogen` output).
3. Per-service supervision policy (restart/backoff defaults, fail-stop vs
   keep-others-running when one service dies).
4. Capabilities required per node (raw UDP for the data plane; `cap_net_admin`
   if gateway/tunnel services are added later).
