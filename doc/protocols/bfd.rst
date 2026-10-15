*******************
BFD on top of SCION
*******************

.. _bfd-specification:

BFD (Bidirectional Forwarding Detection) is a network protocol that is used to
detect faults between two forwarding engines connected by a link.
See :rfc:`5880` and :rfc:`5881`.

BFD can be layered on top of different transport protocols. This document
describes how BFD should be layered on top of SCION.

The Protocol
============

BFD packets, as they are described in the relevant RFCs, should be placed
directly into SCION payload, with no additional intermediate protocol::

    +----------------------+
    | SCION common header  |
    +----------------------+
    | SCION address header |
    +----------------------+
    |  SCION path header   |
    +----------------------+
    |         BFD          |
    +----------------------+

The ``NextHdr`` field in the SCION common header must be set to type ``BFD`` (17).

BFD in SCION Router
===================

Discriminators
--------------

SCION router should choose its discriminators for BFD sessions at random.

Bootstrapping
-------------

BFD bootstrapping process (that is, how incoming BFD packet with ``Your Discriminator``
field equal to zero is mapped to a BFD session) is to be defined by each
particular application.

SCION router, in particular, does bootstrapping in the following way.

It creates one "external" BFD session for each SCION
interface that it owns. Its BFD peer is the SCION router in the neighbouring
AS. The associated BFD packets must use SCION :ref:`OneHopPath <path-type-onehop>`
type.

This kind of BFD session in unambiguously identified by the ID of the SCION interface the
packet was received on.

Furthermore, SCION router creates one "internal" BFD session for every
other SCION router instance within the same AS. The associated BFD packets must use SCION
:ref:`Empty <path-type-empty>` path type.

These BFD sessions are uniquely identified by the source address and port, as it appears
in the underlay UPD header.

NOTE: Using underlay to identify the sibling SCION router is a workaround.
Eventually we don't want SCION protocols to depend on the underlay
protocol. The plan is to use UDP/BFD inside in the SCION payload.

Any other BFD packets (e.g. packets with standard SCION path) are invalid and
must be dropped by the SCION router.

Poll Sequences and RTT Estimation
---------------------------------

SCION router has limited support for Poll Sequences (:rfc:`5880#section-6.5`). Upon receiving a BFD
packet with the Poll (P) bit set, it immediately responds with a packet that has the Final (F) bit
set.

SCION router uses Poll Sequences to estimate round-trip time to its peers. If this feature is
enabled, the Poll bit is periodically set in one of the scheduled BFD packets. The time between
sending the Poll packet and receiving Final from the BFD peer is used to estimate the RTT. If no
Final is received within one transmission interval, the Poll Sequence is aborted an no RTT estimate
provided. In practice this limits the minimum RTT that can be measured reliably to about 75% of the
transmission interval as BFD allows up to 25% jitter.

If a Poll Sequence fails, the interval until the next attempt is increased to up to 10 seconds.
Conversely, if the Poll Sequence succeeds, the poll interval is reduced with a floor at twice the
transmission interval. Poll Sequences may fail because the RTT is higher than the transmission
interval, because a BFD packet was lost, or because the remote router does not support Poll
Sequences.
