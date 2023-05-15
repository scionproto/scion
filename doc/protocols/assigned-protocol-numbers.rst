*******************************
Assigned SCION Protocol Numbers
*******************************

.. _assigned-protocol-numbers:

This document lists the assigned SCION protocol numbers.

Considerations
==============

SCION attempts to take the `IANA’s assigned Internet protocol numbers
<https://perma.cc/FBE8-S2W5>`_ into consideration. Widely used protocols will
have the same protocol number. SCION specific protocol numbers start at ``200``
which makes them very unlikely to clash.

The protocol numbers are used in the :ref:`SCION Header <header-specification>`
to identify the next level protocol.

Assignment
==========

======= ============== =================================
Decimal Keyword        Protocol
======= ============== =================================
0-5                    unassigned
6       TCP/SCION      Transmission Control Protocol over SCION
7-16                   unassigned
17      UDP/SCION      User Datagram Protocol over SCION
18-199                 unassigned
200     HBH            :ref:`SCION Hop-by-Hop Options <hop-by-hop-options>`
201     E2E            :ref:`SCION End-to-End Options <end-to-end-options>`
202     SCMP           :ref:`SCION Control Message Protocol <scmp-specification>`
203     BFD/SCION      :ref:`BFD over SCION <bfd-specification>`
204-252                unassigned
253                    use for experimentation and testing
254                    use for experimentation and testing
255                    reserved
======= ============== =================================
