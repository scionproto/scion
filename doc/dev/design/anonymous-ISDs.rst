************************
Anonymous / Private ISDs
************************

- Author(s): Tilmann Zäschke
- Last updated: 2025-05-02
- Discussion at: :issue:`NNNN`
- Status: **WIP**

Abstract
========
*TL;DR This proposal aims to resolve scaling issues with large numbers
of ISD and core ASes. As a side effect it introducees new privacy
features and removes the need for peering links.*

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
- A-ISD - Anonymous ISD
- A-CORE - The core router(s) of an anonymous ISD. A-ISD provide
  TRCs and local beaconing but (usually) do not participate in the
  normal ISDs' core routing
- BR - Border router
- CS - Control service


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

TODO: Hidden A-CORE require ASes to have multiple parents. Is that possible?
This relates to the question if an A-ISD must have at least one A-CORE in every
ISD. To avoid this we could simply require an ASes' CS to forward segment
queries selectively: destination outside AISD -> ask parent; otherwise
ask local A-CORE.
Again, this requires more complex segment queries where we provide
only the start AS and end AS and get as result UP+CORE+DOWN or even
actual paths. -> Only segments is probably better because
there are many more paths than segments -> I/O problem.

Beaconing
---------


Path Service
------------




Rationale
=========
[A discussion of alternate approaches and the trade-offs, advantages, and disadvantages of the specified approach.]

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
  outside the A-ISD.
- A-ISDs can be nested.

- An AS can join an A-ISD without having to worry about a 2nd AS identifier.
  The normal AS number of an AS remains valid and the only way to address the AS.

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

Implementation
==============
[A description of the steps in the implementation, which components need to be changed and in which order.]
