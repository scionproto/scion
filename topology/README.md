Defining multiple interfaces in the same border router

When defining the links in .topo files, we can specify whether the new interface
for the link should belong to an existing BR or a new one. This is achieve with
an optional ID in the BR name of a link entry.

Without an ID, a new BR with a single interface would be created.
When an ID is specified, the interface would be added to the BR with such ID.

NOTE that the IDs in the .topo files does not correspond to the instance number
of the final topology being generated. The order of the links is what determines
the instance ID.

Consider the following example:
- {a: "1-ff00:0:110",   b: "1-ff00:0:120-1", linkAtoB: CORE}
- {a: "1-ff00:0:120-1", b: "1-ff00:0:130", linkAtoB: CORE}

In the example above, two links are defined resulting in:
- BR 1-ff00:0:110 with a single interface
- BR 1-ff00:0:120 with multiple interfaces
- BR 1-ff00:0:130 with a single interface
