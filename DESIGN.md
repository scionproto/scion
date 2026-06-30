# Design: `testgen` — a Go topology generator

## Status

Proposed. Implements the [PROPOSAL](PROPOSAL.md). Supersedes the Python
`tools/topogen.py` long-term.

## Summary

`testgen` is a new Go CLI that turns a small declarative `.topo` file into a
directory tree that can run a SCION test topology. It is a phased pipeline:
`parse → hydrate → config → service-config → crypto → clab → instructions`.

The pipeline produces, as an explicit intermediate artifact, a **generalized
configuration** (vendor-neutral, modeled on the Anapaya SCION appliance config).
A new **library**, `prism`, turns that generalized configuration into the
service-specific files (router, control, daemon). `prism` is deliberately a
plain Go package so the same code can run inside a service process that wants to
generate its own files.

The MVP supports the existing `.topo` format (including underlay types) and real
crypto generation (via the existing `scion-pki testcrypto` in library mode). The
`clab` and `instructions` phases are wired into the pipeline but are no-ops for
now; containerlab output and gateway support land in follow-ups. The data model
is shaped so those follow-ups are additive.

## Goals

- Faithful replacement for the topo→files job currently done in Python, in
  readable, maintainable Go.
- A clean, ordered, easily-reorderable phase pipeline.
- A reusable `prism` library: `generalized config → service files`, importable
  both by `testgen` and by a service at runtime.
- A pluggable address allocator, defaulting to a containerlab-friendly scheme.
- Forward-compatibility with containerlab output and gateways.

## Non-Goals (MVP)

- Generating run/teardown instructions (phase exists, no-op).
- Gateway / SIG support.
- Docker-compose / supervisor output (the Python tool's other backends).
- Treating the `.topo` format as a stable public API — it is not.

## Tool layout

A tool under `testing/clab/testgen` (CLI at `testing/clab/cmd/testgen`),
following the scio/cmd/scion layout. The phases are internal packages; `prism`
lives outside the tool so it is importable without depending on the CLI.

```
testing/clab/cmd/testgen/main.go   # cobra root command, exit-code handling
testing/clab/cmd/testgen/topo.go   # topo commands
testing/clab/cmd/testgen/...       # all other commands
testing/clab/testgen/
  testgen.go               # Config struct + RunPipeline (ordered phase list)
  out/out.go               # output-dir type: one method per well-known path

  topo/                    # phase 1: parse + validate
    topo.go                # types; UnmarshalYAML for compact endpoints
    parse.go               # ParseTopoFile
    validate.go            # Validate (referential checks)
  hydrate/                 # phase 2: allocation
    hydrate.go
    allocator.go           # Allocator interface + clab default impl
    allocation.go          # network-allocations file types (YAML/JSON)
  config/                  # phase 3: build the generalized config
    build.go               # topo + allocation -> genconf.Config
  crypto/                  # phase 5: wraps scion-pki testcrypto
  clab/                    # phase 6: NO-OP for MVP
  instructions/            # phase 7: NO-OP for MVP


pkg/prism/                 # phases 3+4: generalized-config model AND its renderer
  model.go                 # prism.Config: SCION section + Interfaces section
  encode.go                # YAML and JSON marshal/unmarshal
  prism.go                 # Render(prism.Config) -> []ServiceFile
  router.go                # per-service renderers
  control.go
  daemon.go
```

Rationale `prism` under `pkg/`: they are the reusable contract. `prism` must be
importable by a service process per the proposal, neither may depend on
`testing/clab/testgen`. Dependency direction is strictly `testing/clab/testgen →
pkg/prism`, never the reverse.

## Phase pipeline

The run is an ordered list of `phase(ctx, cfg) error` in `RunPipeline`, each
reading the prior phase's artifacts (in-memory where possible, on-disk where the
artifact is a deliverable). Ordering constraints are documented inline. Phases:

| # | Phase | Input | Output |
|---|-------|-------|--------|
| 1 | parse/validate | `.topo` file | `topo.Topo` (in-mem) |
| 2 | hydrate | `topo.Topo` + allocator | `prism.Config`-ready allocation + `network-allocations.yml` |
| 3 | config | `topo.Topo` + allocation | `prism.Config` per AS + on-disk generalized config |
| 4 | service-config | `prism.Config` (via `prism`) | `*.toml` per service |
| 5 | crypto | `.topo` file | TRCs + certs + keys |
| 6 | clab | `prism.Config` + allocation | *(no-op for MVP)* containerlab topology file |
| 7 | instructions | output dir | *(no-op for MVP)* printed + written run instructions |

### Phase 1 — parse / validate (`topo`)

Mirrors the closed-source testgen and the Python parser. Two separate steps:
`ParseTopoFile` (YAML decode into typed structs) then `Validate` (referential
checks). The format is reproduced exactly so existing `.topo` files work
unchanged.

```go
type Topo struct {
    ASes  map[addr.IA]ASEntry `yaml:"ASes"`
    Links []Link              `yaml:"links"`
}

type ASEntry struct {
    Core          bool        `yaml:"core"`
    Voting        bool        `yaml:"voting"`
    Authoritative bool        `yaml:"authoritative"`
    Issuing       bool        `yaml:"issuing"`
    CertIssuer    addr.IA     `yaml:"cert_issuer"`
    MTU           int         `yaml:"mtu"`
    Underlay      UnderlayType `yaml:"underlay"` // UDP/IPv4 (default) | UDP/IPv6
    // ControlServers int — accepted for compatibility; MVP generates 1.
}

type Link struct {
    A, B     Endpoint
    LinkAtoB LinkType     // CORE | CHILD | PEER (PARENT normalized to CHILD)
    MTU      int          `yaml:"mtu"`
    Underlay UnderlayType `yaml:"underlay"`
    BW       int          `yaml:"bw"` // accepted, currently unused
}
```

The compact endpoint string (`1-ff00:0:120-A#6`) is parsed by a custom
`UnmarshalYAML` into an `Endpoint`:

```go
type Endpoint struct {
    IA   addr.IA // 1-ff00:0:120
    BR   string  // "A" — optional border-router group tag
    IfID uint16  // 6
    Addr string  // optional explicit underlay address (external ASes)
}
```

The `BR` tag is the key semantic carried from the topo: interfaces sharing the
same `(IA, BR)` are grouped onto one border router. Endpoints with no tag each
get their own border router (matching current behavior).

Validation checks (from the appendix and Python parser): every link endpoint
references a known AS; `cert_issuer` points at an issuing AS; voting/issuing/core
flags are internally consistent per ISD (each ISD has ≥1 core, ≥1 voting, ≥1
authoritative, ≥1 issuing); interface IDs are unique within an AS; underlay types
are valid.

### Phase 2 — hydrate (`hydrate`)

Allocates the concrete addressing the topo leaves implicit, and writes a
`network-allocations.yml` record (the audit trail of which AS/link got which
subnet, like the Python `networks.conf`). ISD-AS values are taken from the topo
(they are explicit); hydrate allocates **subnets, service IPs, and ports**.

Allocation is behind a pluggable interface so the scheme can change without
touching downstream phases:

```go
type Allocator interface {
    // Internal network for an AS: hosts its control service, daemon,
    // and border-router internal addresses.
    AS(ia addr.IA) (ASAlloc, error)
    // Point-to-point underlay network for an inter-AS link.
    Link(l topo.Link) (LinkAlloc, error)
}

type ASAlloc struct {
    Subnet      netip.Prefix          // e.g. 10.<isd>.<as-index>.0/24
    Control     netip.AddrPort        // cs address
    Daemon      netip.AddrPort        // sciond address
    BRInternal  map[string]netip.AddrPort // per BR-tag internal addr
    Underlay    topo.UnderlayType
}

type LinkAlloc struct {
    Subnet netip.Prefix    // /31 (v4) or /127 (v6) per link
    A, B   netip.AddrPort  // the two underlay endpoints
}
```

**Default allocator (`clab`)**: a containerlab-friendly scheme — one `/24` per
AS for internal/service traffic and a dedicated small subnet per inter-AS link,
drawn from a configurable base network (default a private range; v6 links from a
ULA base). Ports follow SCION conventions (control `30252`, BR internal `30042`,
router `50000`, dispatched-ports range `31000-32767`). The base network is a CLI
flag (`--network` / `--network-v6`), so the legacy `127.0.0.0/8` loopback scheme
can be requested explicitly if ever needed.

Determinism: allocation is sorted by IA / by link key (stable string ordering),
never by Go map iteration, so repeated runs over the same topo are byte-stable.

### Phase 3 — config (`config` → `pkg/prism.Config`)

Builds the **generalized configuration**, the heart of the design. It is
modeled on the Anapaya SCION appliance config, format-agnostic (the *structure*
is normative; it serializes to both YAML and JSON). It has two sections:

- **`scion`** — the SCION control/data-plane model
  ([ref](https://learn.anapaya.net/docs/technical-documentation/anapaya-appliance/configuration/scion/)).
- **`interfaces`** — the host network interfaces the SCION underlay binds to
  ([ref](https://learn.anapaya.net/docs/technical-documentation/anapaya-appliance/configuration/interfaces/)).

```go
package prism

// Config is the generalized configuration for ONE containerlab host — the
// equivalent of one appliance in the Anapaya model. It describes only the
// elements this host runs, never the rest of the AS.
type Config struct {
    SCION      SCION      `json:"scion"      yaml:"scion"`
    Interfaces Interfaces `json:"interfaces" yaml:"interfaces"`
}

type SCION struct {
    ASes []AS `json:"ases" yaml:"ases"` // ASes this host participates in (usually one)
}

type AS struct {
    ISDAS     addr.IA    `json:"isd_as"   yaml:"isd_as"`
    Core      bool       `json:"core"     yaml:"core"`
    MTU       int        `json:"mtu"      yaml:"mtu"`
    Router    *Router    `json:"router,omitempty"    yaml:"router,omitempty"`    // set iff this host runs a border router
    Control   *Control   `json:"control,omitempty"   yaml:"control,omitempty"`   // set iff this host runs the control service
    Daemon    *Daemon    `json:"daemon,omitempty"    yaml:"daemon,omitempty"`    // set iff this host runs sciond
    Neighbors []Neighbor `json:"neighbors,omitempty" yaml:"neighbors,omitempty"` // this host's external links only
}

type Router struct {
    ID                string         `json:"id" yaml:"id"` // "br-1"
    InternalInterface netip.AddrPort `json:"internal_interface" yaml:"internal_interface"`
    SCIONMTU          int            `json:"scion_mtu"          yaml:"scion_mtu"`
}

type Neighbor struct {
    ISDAS        addr.IA     `json:"neighbor_isd_as" yaml:"neighbor_isd_as"`
    Relationship LinkType    `json:"relationship"    yaml:"relationship"`
    Interfaces   []Interface `json:"interfaces"      yaml:"interfaces"`
}

type Interface struct {
    ID      uint16         `json:"interface_id" yaml:"interface_id"`
    Address netip.AddrPort `json:"address"      yaml:"address"`
    Remote  Remote         `json:"remote"       yaml:"remote"`
    MTU     int            `json:"scion_mtu"    yaml:"scion_mtu"`
}
```

**Granularity.** One `prism.Config` document is emitted per containerlab host,
exactly like one Anapaya appliance config. A test AS maps to **one host per
border router**, and by default an AS has a single border router: all of its
interfaces are grouped onto one default border router unless a link endpoint
carries an explicit suffix tag (e.g. `1-ff00:0:110-A#1`). Each distinct tag
gets its own border router, and therefore its own host. The control service and
daemon are co-located on the default host rather than getting their own
containers, to keep the containerlab topology small. So the default host carries
`router` + `control` + `daemon`, and each tagged host carries just its border
router. (An AS with no border router gets a single host running control +
daemon.) Which optional sections are present *is* the host's role — no separate
selector field is needed. Because the document is purely local,
`prism.Render(cfg)` needs nothing beyond it.

**Host naming.** A host directory is named after the suffix tag of the border
router it runs: a tagged group becomes `host-A`, `host-B`, …; the default
(untagged) group becomes `host-1` and is ordered first, so it is the natural
home for the control service and daemon. Host names are thus *not* derived from
the services they run (a host may run several). The SCION element IDs inside
(`br1-ff00_0_110-1`, `cs1-ff00_0_110-1`, `sd1-ff00_0_110`) are independent and
still appear in the file names and in `topology.json`. For containerlab, node
names are made globally unique by prefixing the AS, e.g. `1-ff00_0_110-host-1`.

The AS-wide `topology.json` — read by every element and listing all of the AS's
border routers and its control service — is deliberately **not** part of the
per-host config (no single appliance knows the whole AS; in a real deployment
the discovery service distributes it). `testgen` generates it from its global
hydrated model and drops a copy into each host directory (see Phase 4).

The **`interfaces`** section captures the underlay binding (ethernets /
loopbacks with CIDR addresses) that hydrate allocated. For the test topology
these correspond to the network interfaces each containerlab node will have;
modeling them now is what lets the follow-up `clab` phase be purely additive.

```go
type Interfaces struct {
    Ethernets []Ethernet `json:"ethernets" yaml:"ethernets"`
    Loopbacks []Loopback `json:"loopbacks" yaml:"loopbacks"`
}
```

The config phase emits one generalized-config document per host to disk (so it
is inspectable and so a single host's config is self-contained for runtime
self-generation), plus the in-memory values handed to phase 4.

### Phase 4 — service-config (`pkg/prism`)

`prism` is a **library** (no CLI). It takes a `prism.Config` for one AS and
returns the service-specific files:

```go
package prism

type ServiceFile struct {
    Name    string // e.g. "cs-1.toml", "br-1.toml", "sd.toml"
    Content []byte
}

// Render produces the service file(s) for the elements present in cfg.
func Render(cfg Config) ([]ServiceFile, error)
```

`prism` renders only the elements present in the host's config, through the
existing service config structs (so output exactly matches what the services
expect):

- **router** (if `AS.Router` set) → `router/config.Config` (`[general]`, `[api]`, `[router]`, BFD…)
- **control** (if `AS.Control` set) → `control/config.Config` (`[general]`, `[beaconing]`, `[ca]`…)
- **daemon** (if `AS.Daemon` set) → `daemon/config.Config` (`[general]`, `[path_db]`, `[trust_db]`…)

By rendering through the real config structs (not free-form templates), prism
stays correct as the service configs evolve. `testgen` calls `prism.Render`
per host in process and `out` writes the files into each host directory; a
service process could call the same function on its own host's config.

The AS-wide **`topology.json`** is *not* produced by prism (a single host's
config doesn't describe the whole AS). `testgen` builds it once per AS from its
global hydrated model — reusing `private/topology/json.Topology` — and writes a
copy into every host directory of that AS.

### Phase 5 — crypto (`crypto`)

Reuses the existing `scion-pki testcrypto`, which already consumes the same
`.topo` format and produces TRCs, CA/root/AS certs, and keys. We expose a thin
`testcrypto.Run(topo, out, ...)` wrapper around the existing unexported
`testcrypto(...)` (a non-behavioral refactor; the cobra `Cmd` keeps calling it)
and the crypto phase calls `Run` in process — no subprocess, no cobra plumbing.
Crypto is independent of phases 2–4 and only needs phase 1's file, so its
ordering is flexible; it is placed after config to match the proposal.

### Phase 6 — clab (`clab`)

Renders a containerlab topology (`<name>.clab.yml`) and a per-host
`network.yaml`, targeting the `testing/clab` node image and controller. One
containerlab node = one host. The node binds its host directory to `/etc/scion`
(where the controller globs the flat `disp_*`/`br*`/`cs*`/`sd.toml` configs it
generates), plus the AS-level `crypto/` and the shared `trcs/`. The controller
reads `network.yaml` to assign the inter-AS link addresses to the data-plane
interfaces (`eth1`, `eth2`, …).

Connectivity:

- **Inter-AS links** are dedicated containerlab veth links between the two
  hosts' data-plane interfaces, addressed from the per-link `/30` (or `/126`).
- **Intra-AS connectivity** (between an AS's hosts when tags create more than
  one) is provided by the containerlab **management network**: each host's
  static management IP is its AS-internal address, so the hosts share an L2
  segment without extra links or bridges. The management subnet (`/16` for v4)
  excludes the link region, and the first subnet slot is reserved for the
  management gateway, so allocations never collide. Longest-prefix routing keeps
  inter-AS traffic on the dedicated links.

The shim **dispatcher** (`disp_*.toml`) is generated on the control host so SVC
(CS/DS) traffic forwarded by remote border routers is received.

### Phase 7 — instructions (no-op MVP)

Will print and write (`<out>/INSTRUCTIONS.md`) how to bring the topology up/down
and where to reach observability endpoints. No-op for MVP. Kept last so it can
describe artifacts produced by all earlier phases.

## Output layout (`out`)

A single `out` type rooted at a base dir (`-o`, default `./gen`), with one
method per well-known path — the pattern from the appendix and `testcrypto`'s
`outConfig`.

```
gen/
  network-allocations.yml          # phase 2 audit trail
  ASff00_0_110/                    # one dir per AS (testcrypto naming)
    crypto/ certs/ keys/           # phase 5 (via testcrypto layout), shared by the AS's hosts
    host-1/                        # default host: named host-1 (untagged group)
      config.yml                   # phase 3 generalized config (this host)
      network.yaml                 # phase 6 interface addressing (clab controller)
      br1-ff00_0_110-1.toml        # phase 4 service files for the elements on this host
      cs1-ff00_0_110-1.toml        #   the default host co-locates control + daemon
      disp_cs1-ff00_0_110-1.toml   #   + the shim dispatcher
      sd.toml
      topology.json                # phase 4 shared runtime topology
    host-A/                        # only present if a link uses the -A suffix
      config.yml
      network.yaml
      br1-ff00_0_110-2.toml
      topology.json
  ISD<n>/trcs/                      # phase 5 TRCs
  <name>.clab.yml                  # phase 6 containerlab topology
  INSTRUCTIONS.md                  # phase 7 (follow-up)
```

AS directory naming uses `addr.FormatIA(..., WithFileSeparator())` to match
`testcrypto`, so crypto output drops into the same per-AS dirs; the per-host
subdirs hang off the AS dir and mount the shared `crypto/` at runtime.

## CLIl

Cobra root command `testgen`, `RunE` runs the pipeline; `SilenceErrors` on the
root with exit-code handling in `main`, matching `scion-pki`.

```
testgen -c topology/default.topo -o gen [flags]
```

Flags (bundled into a `Config` struct, not threaded individually):

| Flag | Default | Purpose |
|------|---------|---------|
| `-c, --topo` | `topology/default.topo` | input topo file |
| `-o, --out` | `gen` | output directory |
| `--network` | clab default v4 base | base IPv4 network for the allocator |
| `--network-v6` | clab default v6 base | base IPv6 network |
| `--as-validity` | `1y` | passed to crypto |
| `--isd-dir` | `false` | group crypto by ISD |

## Forward-compatibility notes

- **Containerlab**: phase 6 is the only missing piece; the generalized config's
  `interfaces` section + per-link subnets are designed to feed it directly.
- **Gateway / SIG**: added as a new optional service in `prism.Config` (a
  `Gateway` field) and a corresponding `prism` renderer; no pipeline reshape.
- **Runtime self-generation**: because `prism` is a pure library over a
  self-contained per-host `config.yml`, a service can generate its own files by
  calling `prism.Render` on its own document.

## Testing

- `topo`: table-driven parse/validate tests, including the `-A/-B/-C` BR tags,
  both underlays, and the existing `tiny.topo` / `default.topo` as fixtures.
- `hydrate`: determinism (stable output across runs) and no-overlap of allocated
  subnets; golden `network-allocations.yml`.
- `prism` model: round-trip YAML↔JSON equality (structure is normative).
- `prism` render: golden TOML/`topology.json` per host for `tiny.topo`; assert
  the rendered structs decode back through the real service config loaders.
- end-to-end: run the full pipeline on `tiny.topo`, assert the output tree and
  that crypto verifies.

## Resolved decisions

1. **Control-server count**: exactly one control service per AS. Multi-CS is a
   possible follow-up; the model does not preclude it.
2. **testcrypto coupling**: an exported `testcrypto.Run` wrapper, called
   in-process by the crypto phase (no subprocess / cobra plumbing).
3. **Generalized config granularity**: one document per containerlab host (=
   one Anapaya appliance), not per AS. An AS spans multiple hosts when it has
   multiple border routers; each host's document describes only its own
   elements. The AS-wide `topology.json` is a separate shared artifact built by
   `testgen`, not part of the per-host config (see the Granularity note under
   Phase 3 and Phase 4).
