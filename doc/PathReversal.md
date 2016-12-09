Handling path reversal correctly in all cases is rather complex. This is a
short document to describe various cases, and the correct processing required,
specifically in the context of a router responding to a packet that is heading
to a revoked link. The aim in all cases is to set the current Hop Field index
to the appropriate entry for the next router.

The table fields below are as follows:
- Router: This specifies the direction of the original packet relative to the
  local AS. E.g. `Egress` means the packet was sent to the router by the local
  AS.
- Revoked IF: This specifies which interface is revoked, relative to the
  direction of the original packet. E.g. `Ingress` means the interface the
  packet arrived over is revoked.
- Incremented: True if this router has already incremented the packet's path.
- Segment changed: True if the path increment changed from one segment to the
  next.
- Xover: True if the current Hop Field has the XOVER bit set.
- Rev incs: How many times the router should increment the path /after/ the
  packet's path has been reversed.

No Xover
--------
The router is not at an Xover point in the path (i.e. it is in the middle of
the path segment, or at the start/end of the path as a whole).

| Router  | Revoked IF | Incremented? | Segment changed? | Xover? | Rev incs |
|---------|------------|--------------|------------------|--------|----------|
| Ingress | Ingress    |              |                  |        | 1        |
| Ingress | Egress     | X            |                  |        | 1        |
| Egress  | Egress     |              |                  |        | 0        |

Core/Shortcut/Peering change over
--------
The router is at an Xover point (i.e. the path is switching from one segment.
to the next).

| Router  | Revoked IF | Incremented? | Segment changed? | Xover? | Rev incs |
|---------|------------|--------------|------------------|--------|----------|
| Ingress | Ingress    |              |                  | X      | 1        |
| Ingress | Egress     | X            | X                | X      | 2        |
| Egress  | Egress     |              |                  | X      | 1        |
