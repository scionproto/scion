*******************
BFD on top of SCION
*******************

BFD (Bidirectional Forwarding Detection) is a network protocol that is used to
detect faults between two forwarding engines connected by a link. (See `rfc5880
<https://tools.ietf.org/html/rfc5880>`__ and `rfc5881
<https://tools.ietf.org/html/rfc5881>`__.)

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
    |      SCION path      |
    +----------------------+
    |         BFD          |
    +----------------------+

The `NextHdr` field in the SCION common header must be set to type `BFD` (17).

Bootstrapping
=============

BFD bootstrapping process (that is, how incoming BFD packets with `Your Discriminator`
field equal to zero are to be mapped to the BFD sessions) is to be defined be each
particular application.

At the moment we define only the bootstrappng process for the SCION border router.

Bootstrapping in SCION Border Router
------------------------------------

SCION border router instance creates one "external" BFD session for each SCION
interface that it owns. Its BFD peer is the SCION border router in the neighbouring
AS. The associated BFD packets must use SCION OneHopPath type.

This kind of BFD session in unambiguously identified by the ID of the SCION interface the
packet was received on.

Furthermore, SCION border router creates one "internal" BFD session for every
other SCION border router within the same AS. The associated BFD packets must use SCION
EmptyPath type.

These BFD sessions are uniquely identified by the source address, as it appears
in the SCION address header.

Any other BFD packets (e.g. packets with standard SCION path) are invalid and
must be dropped by the border router.

Caveats
=======

Note that there is no UDP header, and therefore no ports in BFD/SCION protocol.

The consequence is that there can't be two SCION/BFD-enabled applications (e.g.
two SCION border router instances) sharing the same IP address.
