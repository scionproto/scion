## Why

The existing python based topogen is hard to read and maintain. We want to
rewrite it into a straight forward Go implementation that translates a small
topo file into a set of files to run a testing topology. In our closed source
code, we have already a tool called testgen which does something simmilar. I added
a small description of the tool in the Appendix.

The tool will slightly differ from testgen. Our goal is to output the files such
that they can be used to run a containerlabs topology.

The phase should be:

- parse/validate: the topo
- hydrate: allocate ISD-AS, subnets, IPs for the services, and generate a network allocation file
- config: generate a generalized configuration. Take inspiration from the Anapaya SCION model: <https://learn.anapaya.net/docs/technical-documentation/anapaya-appliance/configuration/scion/>
- service-config: using a new tool, prism, take the generalized configuration and generates the service specific files for router, control, daemon. Make this reusuable such that it could
even be used by a process to generate the service specific files itself.
- crypto: generate TRCs and certificates
- clab: generate the containerlabs topology file
- instructions: print instructions, and also write them into a file in the output directory. How to run the topology, how to tear it down, etc.

For now, the gateway does not need to be supported. It will be added in a follow-up.

## What Changes

### Must Have (MVP)

- the existing topo file needs to be supported. Including the
  underlay types.
- Crypto generation must be supported. It can rely on testcrypto.
- All phases need to be plugged in the tool. Implementation
  of the clab and instruction phases is done in a follow-up
  and are a noop for now.

### Nice to Have (follow-up — design accounts for these)

- containerlabs topology generation is done in a follow-up.
- Gateway support is added in a follow-up.

## Impact

Longterm, the topogen tool will be deprecated and removed.

----------------------

# Appendix

# TestGen — Summary (template for a similar tool)

A CLI (cobra-based) that turns a **small declarative topology file** into a
**fully generated directory tree** ready to run via docker-compose.

## 1. Input — a tiny `.topo` file

A single YAML file describing a SCION network (`tiny.topo` is ~18 lines):

- **`ASes`**: a map keyed by ISD-AS, each with flags/attributes (`core`,
  `voting`, `issuing`, `mtu`, `underlay`, `control_servers`, `ca_architecture`,
  `external`, …).
- **`links`**: a list of edges `{a, b, linkAtoB, underlay, mtu}`, where endpoints
  are compact strings like `1-ff00:0:110#1` (parsed by a custom `UnmarshalYAML`
  into `IA`, `IfID`, optional `Tag`, optional `Address`).

Parsing + validation live in `topo/topo.go`: `ParseTopoFile` (YAML decode) then
`Validate` (referential checks — links must point at known ASes, external ASes
need addresses). The format is explicitly *not* a stable API.

## 2. Processing — sequential phases

The whole run is an ordered pipeline in `cmd/root.go`. Each phase reads prior
outputs from disk and writes new artifacts:

1. **parse + validate** the topo.
2. **convert** — topo → prodgen input + a network/subnet **allocation file**
   (records which AS got which subnet).
3. **prodgen** — compile the prodspec description.
4. **as-list** — generate AS list / sciond addresses.
5. **crypto** — generate TRCs/certs.
6. **config** — render TOML config files (uses prodspec + allocations).
7. **statefiles**.
8. **mkdir** — create the mounted data/log/cache dirs.
9. **docker** — generate `scion-dc.yml` compose file (deliberately **last**, so
   the data dir is created with the local user's permissions, not root's).

Flags toggle phase behavior (`--sig`, `--no_bfd`, `--no-grafana`, `--parca`,
`--coverage`, `--features`, `--tag`, …), bundled into `converter.Config` /
`config.Config` structs rather than threaded individually.

## 3. Output — a generated directory tree

Controlled entirely by the `out` type in `cmd/dir.go`, which is just a base path
with one method per well-known subpath. Everything lands under `gen/` (plus
sibling `gen-certs/`, `gen-data/`, `gen-cache/`, `logs/`, `metrics/`):

```
gen/
  prodgen-input/
  network-allocations.yml
  prodspec.json
  scion-dc.yml          # docker-compose entrypoint
  as_list.yml
  sciond_addresses.json
  <per-service config dirs>
gen-certs/  gen-data/  gen-cache/  logs/  metrics/{prometheus,parca}
```

The tool finishes by printing usage hints (compose up/down commands, and
Grafana/Jaeger/Prometheus URLs).

## The reusable pattern for a new tool

1. **Input**: one small YAML file → typed structs with custom `UnmarshalYAML`
   for compact notation → a `Parse` + a separate `Validate`.
2. **Phases**: a flat, ordered list of `genX(out, cfg)` functions in `RunE`,
   each consuming files written by earlier phases. Easy to add/remove/reorder;
   ordering constraints (like permissions) documented inline.
3. **Output**: an `out string` type with one method per artifact path, all
   rooted at a base dir defaulting to `./` with a `-o` override; final summary
   prints next steps.
