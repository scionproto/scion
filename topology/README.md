# Topology

Brief description of sections in .topo files

## Table of Contents

- [ASes](#ases-section)
- [Links](#links-section)
- [Examples](#examples-section)

## ASes Section

The 'ASes' section describes all the ASes in a topology.
You can specify different attributes like Core, MTU, certificate issuer and number
of services among other things.

**Supported attributes:**
- "core" -- boolean, whether the AS is a core AS
- "voting" -- boolean
- "authoritative" -- boolean
- "issuing" -- boolean, whether the AS is an issuing AS
- "underlay" -- default is UDP/IPv4, can be set to UDP/IPv6, seed does not support IPv6 underlay for now
- "cert_issuer" -- string, the issuer TRC this attribute is necessary if AS is not core
- "MTU" -- integer, the internal MTU of the AS used by seed emulator
- "latency" -- integer, the internal latency in ms of the AS used by seed emulator
- "bandwidth" -- integer, the internal bandwidth in bit/s of the AS used by seed emulator
- "drop" -- float, the internal drop rate (% in range(0.0,1.0)) of the AS used by seed emulator
- "note" -- string, a note for the AS seed emulator will include this in the beacons


## Links Section

The 'links' section describes the links between the BRs of different ASes.

When defining the links in .topo files, we can specify whether the new interface
for the link should belong to an existing BR or a new one. This is achieved with
an optional ID in the BR name of a link entry.

Without an ID, a new BR with a single interface is created.
When an ID is specified, the interface is added to the BR with such ID.

NOTE that the IDs in the .topo files do not correspond to the element ID of the
BRs in the final generated topology. The order of the links is what determines
the element ID.

Consider the following example:

- {a: "1-ff00:0:110",   b: "1-ff00:0:120-1", linkAtoB: CORE}
- {a: "1-ff00:0:120-1", b: "1-ff00:0:130", linkAtoB: CORE}

In the example above, two links are defined resulting in:

- BR 1-ff00:0:110 with a single interface
- BR 1-ff00:0:120 with multiple interfaces
- BR 1-ff00:0:130 with a single interface

**Supported attributes:**
- "a" -- string, necessary, see above
- "b" -- string, necessary, see above
- "linkAtoB" -- string, necessary, the type of link, can be CORE, PEER, CHILD
- "mtu" -- integer, the MTU of the link
- "underlay" -- default is UDP/IPv4, can be set to UDP/IPv6, seed does not support IPv6 underlay for now
- "bandwidth" -- integer, the bandwidth in bit/s of the link used by seed emulator
- "latency" -- integer, the latency in ms of the link used by seed emulator
- "drop" -- float, the drop rate (% in range(0.0,1.0)) of the link used by seed emulator


## Examples Section

This is a list of examples:
 
- [tiny.topo](tiny.topo): A simple topology with 3 ASes and 2 links.
- [tiny4.topo](tiny4.topo): same topology as tiny.topo but using IPv4.
- [wide.topo](wide.topo)
- [default.topo](default.topo)
- [default-no-peers.topo](default-no-peers.topo)
- [peering-test.topo](peering-test.topo): example with one peering link
- [peering-test-multi.topo](peering-test-multi.topo): example with multiple peering links