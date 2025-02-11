# Topology

Brief description of sections in .topo files

## Table of Contents

- [ASes Section](#ases-section)
- [Links Section](#links-section)
- [Examples](#examples)

## ASes Section

The 'ASes' section describes all the ASes in a topology.
You can specify different attributes like Core, MTU, certificate issuer and number
of services among other things.

**Supported attributes:**

- "core" -- boolean, whether the AS is a core AS
- "issuing" -- boolean, whether the AS is an issuing AS
- "underlay" -- default is UDP/IPv4, can be set to UDP/IPv6
- "cert_issuer" -- string, the issuer IA of the CA. This attribute is necessary if AS is not issuing.
- "MTU" -- integer, the internal MTU of the AS

## Links Section

The 'links' section describes the links between the BRs of different ASes.

Consider the following example:

```yaml
links:
  - {a: "1-ff00:0:110",   b: "1-ff00:0:120-1", linkAtoB: CORE}
  - {a: "1-ff00:0:120-1", b: "1-ff00:0:130", linkAtoB: CORE, mtu: 1280}
```

In the example above, two links are defined resulting in:

- BR 1-ff00:0:110 with a single interface
- BR 1-ff00:0:120 with multiple interfaces
- BR 1-ff00:0:130 with a single interface

**Supported attributes:**

- "a" -- string, mandatory, see above
- "b" -- string, mandatory, see above
- "linkAtoB" -- string, mandatory, the type of link, can be CORE, PEER, CHILD
- "mtu" -- integer, the MTU of the link

## Examples

This is a list of examples:

- [tiny.topo](tiny.topo): A simple topology with 3 ASes and 2 links.
- [tiny4.topo](tiny4.topo): same topology as tiny.topo but using IPv4.
- [wide.topo](wide.topo)
- [default.topo](default.topo)
- [default-no-peers.topo](default-no-peers.topo)
- [peering-test.topo](peering-test.topo): example with one peering link
- [peering-test-multi.topo](peering-test-multi.topo): example with multiple peering links
