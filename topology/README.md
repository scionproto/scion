# Topology

Brief description of sections in .topo files

## Table of Contents

- [ASes Section](#ases-section)
- [Links Section](#links-section)
- [borderRouterProperties Section](#border-router-properties-section)
- [Examples](#examples)

## ASes Section

The 'ASes' section describes all the ASes in a topology.
You can specify different attributes like Core, MTU, certificate issuer and number
of services among other things.

**Supported attributes:**

- "core" -- boolean, whether the AS is a core AS
- "voting" -- boolean
- "authoritative" -- boolean
- "issuing" -- boolean, whether the AS is an issuing AS
- "underlay" -- default is UDP/IPv4, can be set to UDP/IPv6 *
- "cert_issuer" -- string, the issuer IA of the CA. This attribute is necessary if AS is not issuing.
- "MTU" -- integer, the internal MTU of the AS *
- "latency" -- integer, the internal latency in ms of the AS *
- "bw" -- integer, the internal bandwidth in bit/s of the AS *
- "drop" -- float, the internal drop rate (% in range(0.0,1.0)) of the AS *
- "note" -- string, a note to be included in the beacons *

Fields marked with * are used by the seed emulator for setting link properties,
with the limitation that seed does not support IPv6.

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
- "mtu" -- integer, the MTU of the link *
- "underlay" -- default is UDP/IPv4, can be set to UDP/IPv6 *
- "bw" -- integer, the bandwidth in bit/s of the link *
- "latency" -- integer, the latency in ms of the link *
- "drop" -- float, the drop rate (% in range(0.0,1.0)) of the link *

Fields marked with * are used by the seed emulator for setting link properties,
with the limitation that seed does not support IPv6.

## Border Router Properties Section

The **optional** 'borderRouterProperties' section describes properties of BRs such as Geolocation.
Entries in the 'borderRouterProperties' section are optional.
This means not every BR defined in the links section must appear in the
'borderRouterProperties' section.

The same string identifiers as in the link section specify the key for a border router.
Though watch out as one border router can have several
SCION interfaces but there can only be one property section for each border router.

Consider the following example from the *default.topo* file for clarification.
In the 'links' section these 6 scion interfaces were specified:

```yaml
"1-ff00:0:120-A#6"
"1-ff00:0:120-A#1"
"1-ff00:0:120-B#2"
"1-ff00:0:120-B#3"
"1-ff00:0:120-B#4"
"1-ff00:0:120#5"
```

Notice though how the 6 scion interfaces are connected to only 3 BorderRouters.
Now in the 'borderRouterProperties' section we can specify properties for each one
of the three BorderRouters like this:

```yaml
"1-ff00:0:120#5":
    geo:
        latitude: 48.858222
        longitude: 2.2945
        address: "Eiffel Tower\n7th arrondissement\nParis\nFrance"
    note: "This is an arbitrary string"
"1-ff00:0:120-A#1":
    geo:
        latitude: 48.858222
        longitude: 2.2945
        address: "Eiffel Tower\n7th arrondissement\nParis\nFrance"
    note: "This is an arbitrary string"
"1-ff00:0:120-B#2":
    geo:
        latitude: 48.858222
        longitude: 2.2945
        address: "Eiffel Tower\n7th arrondissement\nParis\nFrance"
    note: "This is an arbitrary string"
```

Notice that instead of *"1-ff00:0:120-B#2"*
we could have also specified any other interface attached
to the same BorderRouter like *"1-ff00:0:120-B#3"*

**Supported attributes:**

- "geo" -- the geolocation of the Border Router.
geo has three arguments latitude, longitude and address.
This will be added to the staticInfoConfig.json by the seed emulator if set
- "note" -- a string that can contain any string.
This will be added as a note to the Border Router Node by the seed emulator.

## Examples

This is a list of examples:

- [tiny.topo](tiny.topo): A simple topology with 3 ASes and 2 links.
- [tiny4.topo](tiny4.topo): same topology as tiny.topo but using IPv4.
- [wide.topo](wide.topo)
- [default.topo](default.topo)
- [default-no-peers.topo](default-no-peers.topo)
- [peering-test.topo](peering-test.topo): example with one peering link
- [peering-test-multi.topo](peering-test-multi.topo): example with multiple peering links
- [tiny_borderRouterProperties.topo](tiny_borderRouterProperties.topo):
tiny.topo example file with an example of 'borderRouterProperties' Section
- [tiny4_link_properties.topo](tiny4_link_properties.topo):
tiny4.topo example file with an example of how to specify link properties for intra AS network
and inter AS links
