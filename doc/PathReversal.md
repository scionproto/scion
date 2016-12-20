Handling path reversal correctly in all cases is rather complex. This is a
short document to describe various cases, and the correct processing required
to handle reversing a path in the middle (i.e. a router is doing the reversal).
The aim in all cases is to set the current Hop Field index to the appropriate
entry for the next router.

The table fields below are as follows:
- Router: This specifies the direction of the original packet relative to the
  local AS. E.g. `Egress` means the packet was sent to the router by the local
  AS.
- Action: This specifies which action the router is meant to do.
- Incremented: True if this router has incremented the packet's path, meaning
  the common header is updated to point to the next routeable (i.e. not
  VERIFY_ONLY) Hop Field
- Segment changed: True if the path increment changed from one segment to the
  next.
- Xover: True if the current Hop Field has the XOVER bit set.
- Rev incs: How many times the router should increment the path /after/ the
  packet's path has been reversed.

### No Xover

The router is not at an Xover point in the path (i.e. it is in the middle of
the path segment, or at the start/end of the path as a whole).

| Router  | Action          | Incremented? | Segment changed? | Xover? | Rev incs |
|---------|-----------------|--------------|------------------|--------|----------|
| Ingress | Forward/Deliver |              |                  |        | 1        |
| Egress  | Forward         |              |                  |        | 0        |

### Core/Shortcut change over

The router is at an non-peering Xover point. Note that a local destination is
illegal in these cases, so the deliver case is left out.

| Router  | Action          | Incremented? | Segment changed? | Xover? | Rev incs |
|---------|-----------------|--------------|------------------|--------|----------|
| Ingress | Forward         |              |                  | X      | 1        |
| Ingress | Forward         | X            | X                | X      | 2        |
| Egress  | Forward         |              |                  | X      | 1        |

### Peer change over
The router is at a peering Xover point. This differs from the other Xover
points in that local delivery is legal, and no segment change is happening.

| Router  | Action          | Incremented? | Segment changed? | Xover? | Rev incs |
|---------|-----------------|--------------|------------------|--------|----------|
| Ingress | Forward/Deliver |              |                  | X      | 1        |
| Ingress | Forward         | X            |                  | X      | 2        |
| Egress  | Forward         |              |                  | X      | 1        |

### Processing summary

The rules can be simplified to:
- If the packet is at an egress non-Xover point, stop here.
- Increment the reversed path one step.
- Increment the reversed path if it was incremented in the forward direction.
