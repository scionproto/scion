************************************
SCION Extension Header Specification
************************************

This document contains the specification of the SCION extension headers. There
are two extension headers defined, the *Hop-by-Hop (HBH) Options Header* and the
*End-to-End (E2E) Options Header*. A SCION packet can have at most **one** of
each. If both headers are present, the HBH options **MUST** come before the E2E
options. The option header support a variable number of *type-length-value
(TLV)* encoded options.

.. _hop-by-hop-options:

Hop-by-Hop Options Header
=========================

The Hop-by-Hop Options header is used to carry optional information that may be
examined and processed by every node along a packet's delivery path. The
Hop-by-Hop Options header is identified by a Next Header value of ``0`` in the
SCION common header and has the following format::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    NextHdr    |     ExtLen    |            Options            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

NextHdr
    Unsigned 8-bit integer. Identifies the type of header immediately following
    the Hop-by-Hop Options header. Values of this field respect the
    :ref:`Assigned SCION Protocol Numbers <assigned-protocol-numbers>`.
ExtLen
    Unsigned 8-bit integer. Length of the extension header computed as :math:`4B
    \cdot ExtLen`.
Options
    Variable-length field, of length such that the complete Hop-by-Hop Options
    header is an integer multiple of 4 bytes long.  Contains one or more
    TLV-encoded options, as described below.

The Hop-by-Hop Options header is aligned to 4 bytes.

Assigned Option Types
---------------------

The following option types are assigned for Hop-by-Hop options:

======= =================================
Decimal Option
======= =================================
0       :ref:`Pad1 Option <pad-1-option>`
1       :ref:`PadN Option <pad-n-option>`
253     use for experimentation and testing
254     use for experimentation and testing
255     reserved
======= =================================

.. _end-to-end-options:

End-to-End Options Header
=========================

The End-to-end  Options header is used to carry optional information that may be
examined and processed by sender and/or receiver of the packet.  The End-to-end
Options header is identified by a Next Header value of ``0xfd`` in the SCION
common header and has the following format::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    NextHdr    |     ExtLen    |            Options            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

NextHdr
    Unsigned 8-bit integer. Identifies the type of header immediately following
    the Hop-by-Hop Options header. Values of this field respect the
    :ref:`Assigned SCION Protocol Numbers <assigned-protocol-numbers>`.
ExtLen
    Unsigned 8-bit integer. Length of the extension header computed as :math:`4B
    \cdot ExtLen`.
Options
    Variable-length field, of length such that the complete Hop-by-Hop Options
    header is an integer multiple of 4 bytes long.  Contains one or more
    TLV-encoded options, as described below.

The End-to-End Options header is aligned to 4 bytes.

Assigned Option Types
---------------------

The following option types are assigned for End-to-End options:

======= =================================
Decimal Option
======= =================================
0       :ref:`Pad1 Option <pad-1-option>`
1       :ref:`PadN Option <pad-n-option>`
2       :ref:`SCION Packet Authenticator Option <authenticator-option>`
253     use for experimentation and testing
254     use for experimentation and testing
255     reserved
======= =================================

TLV-encoded Options
===================

The hbh and e2e options headers carry a variable number of options that are
type-length-value (TLV) encoded in the following format::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    OptType    |  OptDataLen   |            OptData            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                              ...                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

OptType
    8-bit identifier of the type of option.
OptDataLen
    Unsigned 8-bit integer denoting the length of the ``OptData`` field of this
    option in bytes.
OptData
    Variable-length field. Option-Type specific data.

The sequence of options within a header must be processed strictly in the order
they appear in the header; a receiver must not, for example, scan through the
header looking for a particular kind of option and process that option prior to
processing all preceding ones.

Individual options may have specific alignment requirements, to ensure that
multi-byte values within ``OptData`` fields fall on natural boundaries.  The
alignment requirement of an option is specified using the notation xn+y, meaning
the ``OptType`` must appear at an integer multiple of x bytes from the start of
the header, plus y bytes.  For example::

    2n     means any 2-bytes offset from the start of the header.
    4n+2   means any 4-bytes offset from the start of the header, plus 2
           bytes.

There are two padding options that are used when necessary to align subsequent
options and to pad out the containing header to a multiple of 4 bytes in length.
These padding options must be recognized by all SCION implementations:

.. _pad-1-option:

Pad1 Option
-----------
Alignment requirement: none::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+
    |       0       |
    +-+-+-+-+-+-+-+-+

.. Note::
    The format of the Pad1 option is a special case -- it does not have length
    and value fields.

The Pad1 option is used to insert 1 byte of padding into the Options area of a
header.  If more than one byte of padding is required, the PadN option,
described next, should be used, rather han multiple Pad1 options.

.. _pad-n-option:

PadN Option
-----------
Alignment requirement: none::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |       1       |  OptDataLen   |            OptData            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
    |                              ...                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The PadN option is used to insert two or more bytes of padding into the Options
area of a header.  For N bytes of padding, the ``OptDataLen`` field contains the
value N-2, and the ``OptData`` consists of N-2 zero-valued bytes.
