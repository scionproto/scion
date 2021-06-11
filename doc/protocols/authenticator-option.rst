.. _authenticator-option:

*********************************
SCION Packet Authenticator Option
*********************************

This document describes the Authenticator :ref:`End-to-End option <end-to-end-options>`.
This option allows to add authentication data to a SCION packet, providing
crpytographic assurance of authenticity and and data integrity.
This option only transports the authentication data, i.e., it explicitly is not
concerned with establishing or identifying keys to create or verify the
authentication data.

Format of the Authenticator Option
==================================
Alignment requirement: 4n + 1::


     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    |   OptType=2   |  OptDataLen   |  Algorithm    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Authenticator ...                    |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


OptType
  8-bit value 2
OptDataLen
  Unsigned 8-bit integer denoting the length of the full option data (1 + length of Authenticator). 
  The length depends on algorithm used.
Algorithm
  8-bit identifier of the cryptographic algorithm used.
Authenticator
  Variable-length field, Algorithm specific data.

Algorithms
----------
======= ============= ======================================= =============
Decimal Algorithm     Description                             Reference
======= ============= ======================================= =============
0       AES-CMAC      16-byte MAC                             [`RFC 4493 <https://tools.ietf.org/html/rfc4493>`_]
253                   use for experimentation and testing
254                   use for experimentation and testing
255                   reserved
======= ============= ======================================= =============

Authenticated Data
==================

The authenticator for a packet is computed over the concatenation of

1. the SCION packet's :ref:`Pseudo Header <pseudo-header-upper-layer-checksum>`,
2. the entire upper-layer payload data.
