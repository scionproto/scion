****************
SCION-IP Gateway
****************

The SCION-IP Gateway (SIG) tunnels IP packets over the SCION Internet.

An ingress SIG encapsulates IP packets in a SCION packet and sends it to an egress SIG determined
by the configured routing rules, where the packet is decapsulated and forwarded toward its
destination IP address.
From the perspective of IP, a SIG looks like a router.
From the perspective of SCION, a SIG is a regular application.

.. admonition:: TODO

   SIG Overview and introduction

SIG Framing Protocol
====================

SIG Framing Protocol describes frames sent between two SIG instances.
The IP packets transported via SIG are encapsulated in SIG frames.
There can be multiple IP packets in a single SIG frame.
A single IP packet can also be split into multiple SIG frames.

SIG traffic can be sent over multiple SIG sessions. SIG uses different
sessions to transport different classes of traffic (e.g. priority vs. normal.)

Within each session there may be multiple streams. Streams are useful to
distinguish between traffic sent by different SIG instances. For example,
if SIG is restarted, it will create a new stream ID for each session. That way,
the peer SIG will know that the new frame with a new stream ID does not
carry trailing part of the unfinished IP packet from a different stream.

Each SIG frame has a sequence number. The remote SIG uses the sequence
number to reassemble the contained IP packets.

The Stack
---------

SIG framing protocol on top of SCION and UDP::

  +-----------------------+
  |         SCION         |
  +-----------------------+
  |          UDP          |
  +-----------------------+
  |    SIG frame header   |
  +-----------------------+
  |   SIG frame payload   |
  +-----------------------+

SIG Frame Header
----------------

Each SIG frame starts with SIG frame header with the following format::

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     Version   |    Session    |            Index              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Reserved (12 bits)    |          Stream (20 bits)           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  +                       Sequence number                         +
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

All fields within SIG frame header are in network byte order.

- The ``Version`` field indicates the SIG framing version. It must be set to zero.

- The ``Session`` field indicates the SIG session to be used.

- The ``Index`` field is the byte offset of the first beginning of an IP packet
  within the payload. If no IP packet starts in the payload, for example, if
  the frame contains only a trailing part of an IP packet, the field must be set
  to 0xFFFF.

- The ``Reserved`` field is reserved and must be set to zero.

- The ``Stream`` field, along with the session identifies a unique sequence of
  SIG frames.

- The ``Sequence number`` field indicates a position of the frame within a
  stream. Consecutive frames can be used to reassemble IP packets split among
  multiple frames.

SIG frame payload
-----------------

SIG frame payload may contain multiple IPv4 or IPv6 packets, or parts
thereof. No other types of packets can be encapsulated. The packets are
placed one directly after another, with no padding.

SIG uses IPv4/6 "payload length" field to determine the size of the packet.
To make the processing easier, it is required that the fixed part of the IP header
is in the frame where the IP packet begins. In other words, the initial fragment
of an IPv4 packet must be at least 20 bytes long. Initial fragment of an IPv6
packet must be at least 40 bytes long.

Example
-------

Following example shows three IP packets packed into three SIG frames::

  +----------------------------+---------+---------+---------+----------------+
  | SIG HDR Index=0 Seq=0      | IP4 HDR | payload | IP6 HDR | payload...     |
  +----------------------------+---------+---------+---------+----------------+

  +----------------------------+-----------------+---------+------------------+
  | SIG HDR Index=8 Seq=1      | ...payload (8B) | IP4 HDR | payload...       |
  +----------------------------+-----------------+---------+------------------+

  +----------------------------+------------+
  | SIG HDR Index=0xffff Seq=2 | ...payload |
  +----------------------------+------------+
