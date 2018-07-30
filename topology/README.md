Brief description of sections in .topo files

The 'defaults' section describes configuration that applies to all ASes, like
zookeeper information.

The 'ASes' section describes all the ASes in a topology.
You can specify different attributes like Core, MTU, certificate issuer and number
of services among other things.

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
