************************
Anonymous / Private ISDs
************************

- Author(s): Tilmann Zäschke
- Last updated: 2025-05-02
- Discussion at: :issue:`NNNN`
- Status: **WIP**

Other references:

- Overlapping ISDs https://github.com/scionproto/scion/issues/4293
- Nested ISDs (Scion Book 1, Section 3.6): https://scion-architecture.net/pdf/SCION-book.pdf



Abstract
========
*TL;DR This proposal aims to resolve scaling issues with large numbers
of ISD and core ASes. As a side effect it introducees new privacy
features, censorship protection, and removes the need for peering links.*

The current ISD design combines two main features:

* Isolation Domain with isolated TRC and independent routing
* ISDs are required to be part of the CORE routing network

The trust isolation feature is very useful and presumably the reason why
many (groups of) organisations desire their own ISD.

The second feature is of participating in CORE routing is desirable only
for a small subset of applicant. It also causes several issues:

* The number of ISDs is limited to 65000. A change would require
  modification of the dataplane, i.e. the SCION header.
* Every ISD has at least one CORE AS. A global network with 65000 core ASes
  would break down. We should aim to have at most a few 1000 CORE ASes.
* Having a CORE ASes is undesirable for many non-backbone ISDs because
  they are not interested in transit traffic and need ways to avoid it.

This proposal introduces Anonymous ISDs (or Private ISDs, TBD). The
provide the first feature (independent TRC and routing) without
requiring an ISD number or as CORE AS.

Background
==========
[Introduction of the topic, description of the problem being solved.]

Terminology
-----------
- A-AS - An AS that participates in an A-ISD. The A-AS itself is not anonymous.
- A-ISD - Anonymous ISD
- A-CORE - The core router(s) of an anonymous ISD. A-ISD provide
  TRCs and local beaconing but (usually) do not participate in the
  normal ISDs' core routing
- BR - Border router
- CS - Control service
- P-AS - A private (hidden) AS. P-ASes are part of an A-ISD but not visible from outside
  their A-ISD.


Proposal
========
[A precise statement of the proposed change.]

Building an A-ISD
-----------------
1. We select a number of ASes that want to form an A-ISD.
   These ASes can be from different AISDs, but they must no be separated,
   meaning that they must form a single network where each AS can
   reach every other AS without leaving the network an traversing
   non-group ASes.

2. We chose one or more of the selected ASes to be A-COREs, essentially
   acting as local CORE ASes. These A-COREs must provide TRC and
   beaconing for all ASes in the A-ISD.

Note: An A-ISD can contain ASes (including A-COREs) and link that are not
visible outside of the A-ISD.

Example: Simple A-ISD

![path type filtering figure](fig/anonymous_isd/1-single-A-ISD.png).


Beaconing
---------
The A-CORE performs beaconing just like a normal core AS.
However, PCBs from an A-ISD core are signed/extend with the TRC
of the originating A-CORE instead of the normal ISD core.

ASes can decide to forward PCBs from their A-CORE to additional
links and ASes that are not visible to the surrounding ISD (or
surrounding A-ISD, if any exists) or to links to ASes in other
ISDs (similar to peering).

Path Service
------------
When a path service receives a segment request, it should try to determine
whether the resulting path can be routed inside a known A-ISD.
Unfortunately, with the current API this is not really possible because we
need the source and destination ASes to make that decision.
The path service would also need to maintain a list of all ASes that belong
to any A-AISD to which the local AS belongs to.

So until we have an API that allows giving the source and destination AS,
the path service must return all known segments, whether they
originate from the common ISD or from any nested A-ISD.

Path Construction
-----------------
When constructing a path, an endhost must take care to use segments
from the innermost possible A-ISD.
Otherwise routing wil fail because the BRs will attempt
hop field verification with the innermost certificate.

For example, for any route to an AS that is in the same A-ISD as the
source AS, the path service will return segments that go through the
local A-CORE as well as segments that go through the ISD's core.
The endhost **must** then use the segments that go through the A-CORE.
More specifically, if both ASes are in a hierarchy of nested A-ISDs,
the endhost must use the A-CORE of the innermost A-ISD that it has in
common with the destination AS.

Border Routers
--------------
Border routers need to have some additional state in order to compute the
correct TRC for a given path.

State: For every AS, they need a list that represents the AS's A-ISD
hierarchy, the first entry is the outermost A-ISD and the last entry is the innermost A-ISD.
At each level, we store a reference to the AS's TRC certificate for that A-ISD.

When a border router receives a packet, it looks at the fist and last AS in the
path header. For both ASes it looks up the hierarchy list.
- If at least one of the does not have a list (meaning it is not in any A-ISD known to the BR)
  the we use the normal (rotted in the ISD's TRC) AS certificate for both.
- If they both have a list, then we walk through both lists until they differ.
  THis gives us the deepest common A-ISD and the associate certificate.
- The lists cannot differ in the first entry, that would violate the
  A-ISD-hierarchy principle.

Private Links and Private ASes
------------------------------
A-ISD allow to hide links and ASes from the rest of the ISD.
These are called private links (P-Links) and private ASes (P-AS).

Hiding these is achieved by simply excluding them from any PCBs that come from
outside the A-ISD.
Every P-AS needs an AS number. Unfortunately, this needs to be globally unique,
so the parent ISD can see that the AS exists. However, to hide it's identity,
the AS can use the ISD code of a different ISD. There could even be a dedicated
ISD code for private ASed.

QUESTION: Can we vahe hidden A-COREs? Why would we need that?
Hidden A-COREs require ASes to have multiple parents.
Specifically, any non-hidden AS needs a non-hidden CORE that is visible from the outside.

Is it possible yto have multiple parents?
This relates to the question if an A-ISD must have at least one A-CORE in every
ISD. To avoid this we could simply require an ASes' CS to forward segment
queries selectively: destination outside AISD -> ask parent; otherwise
ask local A-CORE.
Again, this requires more complex segment queries where we provide
only the start AS and end AS and get as result UP+CORE+DOWN or even
actual paths. -> Only segments is probably better because
there are many more paths than segments -> I/O problem.

Rationale
=========
[A discussion of alternate approaches and the trade-offs, advantages, and disadvantages of the specified approach.]

Alternative: Use private ISD numbers (Jonghoon)
-----------------------------------------------
For internal communication, an A-ISD could use ISD numbers from the private range (not
globally unique).
- This requires AS numbers to be globally unique
- When receiving PCBs or on the BR, we could use this to identify the correct TRC / certificate


Advantages
----------

- A-ISDs do not need an identifier (saves space in the 16bit ISD number space)
- A-ISDs do not (usually) have a CORE-AS.

  - That improves scalability: people can have an (A)ISD without impacting scalability
  - A-ISDs do not need to worry about transit traffic.

- A-ISDs provide isolation + independency of TRC and routing
- A-ISDs can cross ISD boundaries as long as there is a physical link.
  They can probably replace current peering links.

- Privacy: An A-ISD can contain any number of ASes and link that are not visible
  outside the A-ISD (private ASes -> P-ASes).
- A-ISDs can be nested.

- An AS can join an A-ISD without having to worry about a 2nd AS identifier.
  The normal AS number of an AS remains valid and the only way to address the AS.

- A-ISDs can even be hidden from individual endhosts in ASes that participate
  in the A-ISD.
  Either the path server can choose not to give A-ISD segments to the endhost,
  or the anonymous path server itself could be hidden from some endhosts such
  that the endhost would contact a different path server that serves only
  non-A-ISD segments.
- Similar to hiding A-ISDs from specific endhosts in A-ASes, we can also hide
  the A-ISDs from child ASes of A-ASes.

- No change to endhost libraries required.

Disadvantages
-------------
- AISD have no ISD number. Any AS inside an A-ISD mus have a globally unique
  AS number from some ISD.
  However, if it is okay for the AS to not be globally addressable,
  it does not need to be connected to that ISD or even be visible to that
  ISD.
- Border routers need more state and compute. They need to know all ASes in
  all A-AISDs in which the local AS participates.
  They also need a more complex algorithm to determine which certificate/TRC
  to use.


Limitations
-----------

A-ISDs cannot arbitrarily overlap. Any given AS can participate only in
one A-ISD hierarchy.
The problem is that BRs need to be able to authenticate hop fields.
To do so, they need to determine which certificate to use.
They can determine the correct certificate by looking at the first + last
AS in a given path. The correct TRC is then the "innermost" A-ISD that
contains both ASes. If the ASes could both be in multiple A-ISD, then
the BR cannot uniquely determine the correct TRC.

Possible "solutions":

* Add a unique certificate ID to the SCION packet header. This would
  immediately solve the problem and also avoid the need for the BR to
  store AS->TRC mappings for all local A-ISDs.
* BRs should also check all A-COREs in the paths. If A-COREs are
  restricted to belong to only one A-ISD-hierarchy, then this would
  allow determining the correct certificate even if other ASes
  belong to multiple A-ISD hierarchies. Unfortunately this breaks
  if we allow segments without A-COREs, for example when optimizing
  path with shortcuts or on-path.
* Is it possible to have two or more TRCs in a certificate? I.e. can we
  create a certificate that can be verified with the normal A-ISD, or,
  if that is not available, with one or more A-ISDs?
  We could use this certificate to sign all segments, whether they are
  created in the ISD or in a local A-ISD.
* Ask BR to brute try out multiple certificates. This is expensive,
  but the number of possible certificate per AS should be small (every
  AS is likely to be in only a small number of ISD + A-ISDs).
* Allow BRs to forward unchecked traffic indide A-ISDs.


Compatibility
=============
[A discussion of breaking changes and how this change can be deployed.]

There are no conflicts with existing stuff.

Implementation
==============
[A description of the steps in the implementation, which components need to be changed and in which order.]

1. Improve CS to allow end-to-end segment requests. Stitching is not necessary,
   but the request should return UP+CORE+DOWN segments in one request.
2. The control service needs to be extended with A-CORE functionality:

   - Facility to register A-ASes and their links and to communicate
     this to other ASes in the local A-ISD
   - Segment request: When receiving a segment request, if being/end AS are in
     the local A-ISD, return only A-ISD segments. If the end-AS is outside the A-ISD
     forward the request to the parent AS outside the A-ISD, (or return cached
     segments fro outside the A-ISD).
   - Optional: Add capability for an AS to have multiple parents, one per ISD.
     If a CS receives a segment request for outside the local A-ISD, it can decide
     for forward the request to multiple A-COREs, at most one per ISD that the A-ISD
     participates in. A-COREs can be each other's parent (parent must be in different ISD).
     This allows any A-AS member to transparently use any ISD that participates
     in the A-ISD.
     **TODO move this to design section**
     **TODO how does path stitching(beaconing) work? -> Same as peering ...?!

3. Border routers:

   - They need to obtain lists of all ASes in the local A-ISDs.
   - Update path authentication such that



