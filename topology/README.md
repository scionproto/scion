# Topology

Brief description of sections in .topo files

The 'ASes' section describes all the ASes in a topology.
You can specify different attributes like Core, MTU, certificate issuer and number
of services among other things.

The 'links' section describes the links between the BRs of different ASes.

When defining the links in .topo files, we can specify whether the new interface
for the link should belong to an existing BR or a new one. This is achieved with
an optional ID in the BR name of a link entry.

Without an ID, a new BR with a single interface is created.
When an ID is specified, the interface is added to the BR with such ID.

Link ids can also optionally be specified by adding a number after "#". Overall, the syntax is as follows:

<ISD-ID>-ff00:0:<AS-ID>[-<BR-ID>][#<IF-ID>]

Example: `1-ff00:0:120-5#2` is:
* of ISD 1
* AS 120
* brige 5
* interface id 2


Consider the following example:

- {a: "1-ff00:0:110",   b: "1-ff00:0:120-1", linkAtoB: CORE}
- {a: "1-ff00:0:120-1", b: "1-ff00:0:130", linkAtoB: CORE}

In the example above, two links are defined resulting in:

- BR 1-ff00:0:110 with a single interface
- BR 1-ff00:0:120 with multiple interfaces
- BR 1-ff00:0:130 with a single interface
