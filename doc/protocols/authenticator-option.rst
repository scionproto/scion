.. _authenticator-option:

*********************************
SCION Packet Authenticator Option
*********************************

This document describes the Authenticator :ref:`End-to-End option <end-to-end-options>`.
This option allows to add authentication data to a SCION packet to provide
cryptographic assurance of authenticity and data integrity and to provide
protection against replays.

The Authenticator option protects integrity of the :ref:`SCION Common Header <scion-common-header>`,
the :ref:`SCION Address Header <scion-address-header>`, the SCION Path as well
as the upper layer payload.
:ref:`SCION Extension Headers <scion-extension-headers>` are **not** protected.

In the current form, this option is primarily intended to be used in
conjunction with DRKey which provides shared secrets without explicit key
exchange.
The option is designed to allow future extensions to make it applicable also in
scenarios with explicitly set up shared state, analogous to IPSec.

.. TODO Add detailed references to DRKey docs once this is converted to RST.


Format of the Authenticator Option
==================================
Alignment requirement: 4n + 2::


     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                                    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                                    |   OptType=2   |  OptDataLen   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Security Parameter Index                    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Algorithm  |      RSV      |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                    Timestamp / Sequence Number                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Authenticator ...                    |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

OptType
  8-bit value 2
OptDataLen
  Unsigned 8-bit integer denoting the length in bytes of the full option data
  (12 + length of Authenticator).
  The length depends on algorithm used.
Timestamp / Sequence Number:
  Unsigned 48-bit integer value.
  The Timestamp / Sequence Number field contains a value for each packet that
  can be used for replay detection by the receiver.
  The detailed interpretation of the Timestamp / Sequence Number field depends on the :ref:`SPI <spao-spi>`.

  When used with a DRKey :ref:`SPI <spao-spi>`, the field represents a relative Timestamp (*Ts*),
  counting the nanoseconds since the starting time of the associated DRKey :ref:`Epoch<drkey-epoch>`.
  (See :ref:`Appendix<spao-appendix>` for a more detailed explanation about the field interpretation).
  The timestamp MAY be used to compute the absolute time (*AbsTime*) value,
  which corresponds to the time when the packet was sent.
  The section :ref:`Absolute time derivation<spao-absTime>` describes the derivation of *AbsTime* and
  the associated DRKey.

  The receiver SHOULD drop packets with *AbsTime* outside of a locally chosen
  range around the current time.

  The sender SHOULD ensure the uniqueness of the absolute time (*AbsTime*) per identical packet.
  The receiver will use the *AbsTime* for replay detection and, thus,
  it SHOULD drop identical packets, i.e. packets with a duplicate:

  .. math::
    (\mathrm{SRC\ ISD, SRC\ AS, SrcHostAddr, Authenticator})

  .. note::
    In other words, the duplicate suppression would happen within the
    acceptance windows considering identical values for the Authenticator field, which is
    computed based on packet contents, such as the Timestamp (used to derive the *AbsTime*)
    and the upper layer payload
    (see the section :ref:`Authenticated Data<authenticated-data>`).

    When used with a non-DRKey :ref:`SPI <spao-spi>`, this field is used as
    a wrapping counter and replay detection is based on sliding window of expected counter values.
    This use case is not specified in detail here. Extending this specification
    in the future will closely follow [`RFC 4302 <https://tools.ietf.org/html/rfc4302>`_].

Security Parameter Index (SPI)
  32-bit identifier for the key used for this authentication option.
  See :ref:`spao-spi`.
Algorithm
  8-bit identifier of the cryptographic algorithm used. See :ref:`spao-algorithms`.
Authenticator
  This variable-length field contains the Algorithm-specific message
  authentication code (MAC), combination of hash and MAC, signature, or other
  integrity check value.
RSV
  These bits are reserved for future use and MUST be set to zero by the sender
  and SHOULD be ignored by the recipient.

.. _spao-spi:

Security Parameter Index
------------------------

The Security Parameter Index (SPI) identifies the key used for this
authentication option.

The SPI value of zero (0) is reserved for local, implementation-specific use
and MUST NOT be sent on the wire.

SPI values in the range :math:`1 \ldots 2^{21}-1` identify a DRKey.

Otherwise, the SPI is an arbitrary value that is used by a receiver to identify
the security association to which an incoming packet is bound.
This use case is not specified in detail here. Extending this specification in
the future will closely follow [`RFC 4302 <https://tools.ietf.org/html/rfc4302>`_].

.. _spao-spi-drkey:

DRKey
^^^^^

.. TODO Add detailed references to DRKey docs once this is converted to RST.

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |             0       |R R R T D|       Protocol Identifier     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

R
  These bits are reserved for future use and MUST be set to zero by the sender
  and SHOULD be ignored by the recipient.

T
  Type. Specifies the type of the key in the DRKey key hierarchy.

    * ``0``: AS-to-host key
    * ``1``: host-to-host key
D
  Direction. Specifies which the deriving side and which is the fetching side.

    * ``0``: sender-side key derivation
    * ``1``: receiver-side key derivation
Protocol Identifier
  16-bit protocol identifier. Note that 0 is a reserved protocol number and
  cannot occur here.

.. _spao-absTime:

Absolute time and DRKey selection
=================================

This section proposes an implementation method to find out the Security Association from the
SPAO metadata information, i.e., to select the DRKey to authenticate the packet.

Firstly, the receiver entity defines an *acceptance window*.
An *acceptance window* (aw) is a time range of width *a* around the receiver's current time *T*,
i.e.,:

:math:`aw := [T-a/2, T+a/2)`


[i] The acceptance window is equal or smaller than the minimum DRKey epoch length.

The receiver entity derives the absolute timestamp and selects the associated DRKey by:

1. Given a time instant *T*, considering:

   - Epoch :math:`E_{i}` as the one whose time range includes *T*.
   - Epoch :math:`E_{i-1}` as the prior epoch to :math:`E_{i}`.
   - Epoch :math:`E_{i+1}` as the subsequent epoch to :math:`E_{i}`.

2. Adding the relative timestamp (*RelTime*) (the one in :ref:`SPAO Header<authenticator-option>`) to
   the start time for :math:`E_{i-1}`, :math:`E_{i}` and :math:`E_{i+1}`,
   computing the respective *absolute times* (*AbsTime*):
   :math:`at_{i-1}`, :math:`at_{i}` and :math:`at_{i+1}`.
3. Given [i] at most one *absolute time* will be within *aw*.
4. The candidate DRKey is the key whose epoch is associated to *AbsTime*,
   e.g., if *AbsTime* is :math:`at_{i-1}` the key belonging to :math:`E_{i-1}`.

Note that :math:`at_{i-1}` might, for instance be within the :ref:`Grace period<drkey-grace>`, i.e.,
overlapping at :math:`E_{i}`. Nevertheless, due to [i] we can unambiguously distinguish it.


.. _authenticated-data:

Authenticated Data
==================

The authenticator for a packet is computed over the immutable fields of
the SCION packet's :ref:`Common Header <scion-common-header>`, :ref:`Address
Header <scion-address-header>` and the path.

.. note::
   It would be possible to also include mutable but predictable fields in the
   authenticator, like for example the ``CurrINF``, ``CurrHF`` and ``SegID``
   fields of the SCION path (see 4. below).
   As predicting these fields can incur additional overhead, they are not
   included in the authenticator by default. This could however be added as an
   optional feature in the future (e.g. controlled with a flag in the reserved
   bits or by selecting it depending on the algorithm type).

The extension headers are explicitly not protected and consequently, the
``NextHdr`` and ``PayloadLen`` fields of the common header are ignored.
Instead, the upper-layer protocol identifier and the upper layer packet length
are included explicitly, analogous the treatment in the :ref:`Pseudo Header <pseudo-header-upper-layer-checksum>`.

The input for the MAC is the concatenation of the following items:

1. The Authenticator Option Metadata::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  HdrLen       |  Upper Layer  |    Upper-Layer Packet Length  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Algorithm  |      RSV      |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                 Timestamp / Sequence Number                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  HdrLen
    Copied from :ref:`SCION Common Header <scion-common-header>`.
    This is otherwise skipped (see treatment of Common Header below)
    but is required to be included to prevent length extension of the
    path.
  Upper Layer
    The protocol identifier associated with the upper-layer protocol.
    This field can differ from the ``NextHdr`` field in the SCION header if
    extensions are present.
  Upper-Layer Packet Length
    The length of the upper-layer data, i.e. ``PayloadLen`` minus the sum of
    the extension header lengths.

  The other fields are the fields of the authentication option defined above.

2. The :ref:`SCION Common Header <scion-common-header>` without the second
   row::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |Version|   TC w\o ECN  |                FlowID                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    PathType   |DT |DL |ST |SL |              RSV              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

  TC w\\o ECN
    The TrafficClass field from the Common Header, but with the ECN bit set to 0.


3. The :ref:`SCION Address Header <scion-address-header>`

  .. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            DstISD             |                               | -
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +  \
    |                             DstAS                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+     unless used with DRKey
    |            SrcISD             |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +  /
    |                             SrcAS                             | -
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    DstHostAddr (variable Len)                 | - unless used with DRKey and not (T=0 and D=1)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    SrcHostAddr (variable Len)                 | - unless used with DRKey and not (T=0 and D=0)
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


  When used with a :ref:`SPI referring to a DRKey <spao-spi-drkey>`,
  the source and destination ISD/AS, as well one or both of the host addresses
  are protected by the key derivation and are skipped in the input to the MAC.

  If an end-to-end key is used (T=1), both source and destination host
  addresses are skipped.
  If an AS-to-host key is used (T=0), the host address for the deriving side is
  not included in the key derivation and must be included in the MAC
  computation.
  With sender-side key derivation (D=0), the source host address is included in
  the MAC input.
  With receiver-side key derivation (D=1), the destination host address is
  included in the MAC input.

4. The Path, with all mutable fields set to "zero". This is defined separately
   per Path Type:

  * :ref:`path-type-scion`: the following mutable fields are zeroed:
      - PathMeta Header: ``CurrINF``, ``CurrHF``
      - Info Fields: ``SegID``
      - Hop Fields: router alert flags

  * :ref:`path-type-onehop`:
      - First Hop Field: router alert flags
      - Second Hop Field

5. The upper layer payload

.. _spao-algorithms:

Algorithms
==========
======= ============== ======================================= =============
Decimal Algorithm      Description                             Reference
======= ============== ======================================= =============
0       AES-CMAC       16-byte MAC                             [`RFC 4493 <https://tools.ietf.org/html/rfc4493>`_]
1       SHA1-AES-CBC   20-byte SHA1 hash, 16-byte MAC          :ref:`spao-hash-then-mac`
253                    use for experimentation and testing
254                    use for experimentation and testing
255                    reserved
======= ============== ======================================= =============


.. _spao-hash-then-mac:

SHA1-AES-CBC
-------------

The ``SHA1-AES-CBC`` algorithm operates in a two staged fashion; the bulk of
the authenticated data is hashed and the resulting hash is included in the
option header. The MAC is computed over only the most relevant header fields
and the hash as input. This allows to quickly determine the authenticity of the
packet, deferring the data integrity check of the full packet.

The format of the authenticator data for the ``SHA1-AES-CBC`` algorithm is:

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                                                               |
    |                        SHA1 hash (20 byte)                    |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                      AES-CBC MAC (16 byte)                    |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The SHA1 hash is computed over:

* the SCION Common Header (2.)
* the Path (4.)
* the upper layer payload (5.)

The input to the MAC is:

* the Authenticator Option Metadata (1., 12 bytes)
* the Address Type/Length fields (1 byte, padded to 4 bytes)
  and the Address Header (3., 0-48 bytes).

  The Address Type/Length fields are extracted from the third row of
  the Common Header, with the remaining fields zeroed out::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       0       |DT |DL |ST |SL |              0                |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


  As discussed above, the source and/or destination address may be skipped when
  used with a :ref:`SPI referring to a DRKey <spao-spi-drkey>`. If both
  addresses are skipped, the row for the Address Type/Length fields byte is
  also skipped.
* the SHA1 hash (20 bytes)

Observe that when used with suitable a :ref:`SPI referring to a DRKey
<spao-spi-drkey>`, the address header may be left empty, resulting in an ideal
32-byte input size for the AES-CBC MAC.

This scheme is safe from length extension attacks on the AES-CBC MAC; except
for the addresses, all fields are of a fixed size. The length of the address
fields is included in the first block of the AES-CBC MAC.
It is visible from the metadata whether the addresses are to be skipped from
the MAC input, as discussed above, so that also in this case no length
extension attacks are possible.

.. _spao-appendix:

Appendix: Design Rationale
==========================

The following goals/constraints led to this design:

- include a timestamp / sequence number to uniquely identify packets.

  - timestamp should be accurate enough to allow dropping obviously old packets
  - sequence number should be long enough to allow sliding window replay
    suppression like in IPSec

- SPI with around 32-bits like in IPSec -- exact range does not matter as it's
  locally chosen

- reasonable field alignment with little padding with 4n + 2 option alignment
  (to avoid padding before first option)

- 2 AES blocks or fewer for LightningFilter use case (SHA1-AES-CBC with DRKey)

  - Require as little copying as possible to check MAC in this use case. Hash
    directly following the option.

- this does not appear to work with less than 3 rows. We use the available
  room to make a 48-bit Timestamp / Sequence Number field and leave one
  reserved byte for future extensions (e.g. flags or extended timestamp or
  sequence number).
  The SPI comes first as we don't need to include it in the MAC computation and
  don't want it between the other fields and the SHA1 hash.

- When the Timestamp / Sequence Number field is used with DRKey SPI, the 48-bits in the field allow to
  cover the maximum DRKey epoch length plus the :ref:`Grace period<drkey-grace>`
  with granularity of 1 nanosecond, since:

  .. math::
        (3 \times 24 \times 60 \times 60 + 5) \times 10^9 < {2^{48}}

- When the Timestamp / Sequence Number field is used with DRKey SPI, the application can use a clock that is less
  accurate than 1 nanosecond and fill out the less significant bits with a counter.
