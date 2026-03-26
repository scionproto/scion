*********************
IP in SCION Tunneling
*********************

Introduction
============

The SCION IP Gateway (SIG) enables IP packets to be tunneled over SCION to support communication between hosts that do not run a SCION implementation. A SIG acts as a router from the perspective of IP, whilst acting as SCION endpoint from the perspective of the SCION network. It is typically deployed inside the same AS-internal network as its non-SCION hosts, or at the edge of an enterprise network.

Tunneling IP traffic over SCION requires a pair of SIGs and it involves the following steps:

1. A sender sends an IP packet towards an IP destination.

2. The IP packet reaches a SIG in the sender’s network via standard IP routing.

3. Based on the destination IP address, the source (ingress) SIG determines the destination (egress) SIG's ISD-AS endpoint address. To achieve this, SIGs are administratively configured with a set of partner ASes, discover SIGs present at these ASes via :ref:`SIG Discovery <sig-discovery>`, and exchange IP prefixes using :ref:`SGRP <sgrp>`.

4. The ingress SIG encapsulates the original IP packet within one or more SCION packets and sends them to the egress SIG. The ingress SIG performs SCION path lookups and selects a SCION path to the egress SIG.

5. The egress SIG receives the SCION packet or packets and decapsulates the original IP packet. It then forwards the packet to the final IP destination using standard IP routing.

This protocol is designed to:

- provide independence from the underlying SCION path MTU which can increase and decrease over time.
- provide fast detection of packet loss and subsequent recovery of decapsulation for packets that weren't lost.
- support for multiple streams within a framing session such that independent packet sequences be tunneled in parallel.

SIGs discover remote SIGs via :ref:`SIG Discovery <sig-discovery>` and then map IP prefixes to SCION ASes using :ref:`SGRP <sgrp>`.


.. _sig-discovery:

SIG Discovery
=============

Before exchanging IP prefixes, a SIG must discover the SIG instances in each remote AS. It does so by periodically sending a ``DiscoveryService.Gateways`` RPC to the remote AS's control service. Based on the AS's topology information, the control service replies with a list of gateways, each described by a control address, a data address, a probe address, and an optional set of allowed AS interfaces. The discovery service is defined in `proto/discovery/v1/discovery.proto <https://github.com/scionproto/scion/blob/master/proto/discovery/v1/discovery.proto>`_. The RPC can be served over gRPC or ConnectRPC (see the ``rpc`` configuration in :doc:`/manuals/gateway`).

A SIG makes itself discoverable by being declared in the AS's ``topology.json`` file (under the ``sigs`` key) with its control, data, and probe addresses.


.. _sgrp:

SCION Gateway Routing Protocol (SGRP)
=====================================

The SCION Gateway Routing Protocol (SGRP) enables SIGs to map IP prefixes to SCION ASes. SGRP operates between SIGs that have already been discovered via :ref:`SIG Discovery <sig-discovery>`.

A SIG participating in SGRP between two SCION ASes does the following:

1. It periodically queries each discovered SIG in the remote AS via the ``IPPrefixesService.Prefixes`` RPC to learn the IP prefixes that it announces. From that, the local SIG builds a mapping of IP prefix to remote SIGs.

2. When queried by a remote SIG, the local SIG replies with the set of IP prefixes it wants to announce.

The set of announced IP prefixes can be statically configured via the IP routing policy file (see :doc:`/manuals/gateway`).

SGRP Messages
-------------

Prefix exchange uses the ``IPPrefixesService.Prefixes`` RPC, defined in `proto/gateway/v1/prefix.proto <https://github.com/scionproto/scion/blob/master/proto/gateway/v1/prefix.proto>`_.

A requesting SIG sends a ``PrefixesRequest`` to a discovered remote SIG's control address. The request contains a ``etag`` field: a hash of the prefix set from the previous response (or empty on the first request).

The remote SIG determines which IP prefixes to advertise based on the requesting AS's identity (extracted from the SCION peer address) and the local routing policy. It replies with a ``PrefixesResponse`` containing:

- A list of IP prefixes, each consisting of a raw IP address (4 bytes for IPv4, 16 bytes for IPv6) and a prefix length (e.g., 24 for a /24 network).
- An ``etag`` for the returned prefix set. If the request's ``etag`` matches the current set, the prefix list is empty and the client reuses its cached prefixes.


SIG Framing Protocol
====================

IP packets are encapsulated into SIG frames, which are sent as SCION/UDP datagrams.

There may be multiple IP packets in a single SIG frame, and a single IP packet may be split into multiple SIG frames.

The ingress SIG initiates unidirectional packet flows to the egress SIG simply by sending the corresponding SIG frames. There is no handshake. The egress SIG, should it accept the traffic, instantiates the necessary resources on-demand to process each flow. Each such flow forms an independent sequence of packets (a stream) ordered by an incrementing sequence number. Between a given SIG ingress/egress pair, a (session ID, stream ID) pair uniquely identifies a stream.

To preserve performance, IP packets that form a sequence leave the egress SIG in the order in which they entered the ingress SIG. To that end:

- The ingress SIG encapsulates IP packets that cannot be proven independent (e.g., with the same 5-tuple consisting of protocol number, source address, destination address, source port, destination port) in the same stream.
- The ingress SIG encapsulates IP packets to a given stream in the order in which they were received.
- The ingress SIG sends all frames of a given stream over the same SCION path.
- The egress SIG reassembles and forward packets from each stream, ordered by frame sequence number and by packet within each frame.

The session ID part of the (session ID, stream ID) pair has an implementation defined meaning. Existing implementations use different session IDs for different traffic classes: the ingress SIG is responsible for assigning a traffic class. On the egress SIG side, the session ID may inform the processing of frames and enables per-class metrics.

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
  |     Version   |  Session ID   |            Index              |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |   Reserved (12 bits)    |        Stream ID (20 bits)          |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  +                       Sequence number                         +
  |                                                               |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

All fields within SIG frame header are in network byte order.

- ``Version`` (8 bits) indicates the SIG framing version. It MUST be set to zero if following this specification.
- ``Session ID`` (8 bits) identifies a tunneling session between a pair of SIGs.
- ``Index`` (16 bits) is the byte offset of the first beginning of an IP packet within the payload. If no IP packet starts in the payload, e.g. if the frame contains only the middle or trailing part of an IP packet, the field MUST be set to 0xFFFF.
- ``Reserved`` (12 bits): it MUST be set to zero.
- ``Stream ID`` (20 bits), along with the session, it identifies a unique sequence of SIG frames. Frames from the same stream are, on the egress SIG, put into the same reassembly queue. There may be multiple streams per session.
- ``Sequence Number`` (64 bits) indicates the position of the frame within a stream. Consecutive frames of a given stream have consecutive sequence numbers. IP packets split among multiple frames are re-assembled by concatenating the payloads of consecutive frames.

A SIG MAY drop frames. In the current implementation, the egress SIG does not buffer frames that are received out-of-order. Instead it drops any out-of-order and following frames until it finds the beginning of a new encapsulated IP packet.

SIG frame payload
-----------------

The SIG frame payload may contain multiple IPv4 or IPv6 packets, or parts thereof. No other types of packets can be encapsulated. The packets are placed one directly after another, with no padding. Multicast traffic is not yet supported.

The SIG uses IPv4/6 "payload length" field to determine the size of the packet. To make the processing easier, the fixed part of the IP header MUST be in the frame where the IP packet begins. In other words, the initial fragment of an IPv4 packet must be at least 20 bytes long, and the initial fragment of an IPv6 packet must be at least 40 bytes long.

Example
-------

Following example shows three IP packets packed into three SIG frames:

  +----------------------------+---------+---------+---------+----------------+
  | SIG HDR Index=0 Seq=0      | IP4 HDR | payload | IP6 HDR | payload...     |
  +----------------------------+---------+---------+---------+----------------+

  +----------------------------+-----------------+---------+------------------+
  | SIG HDR Index=8 Seq=1      | ...payload (8B) | IP4 HDR | payload...       |
  +----------------------------+-----------------+---------+------------------+

  +----------------------------+------------+
  | SIG HDR Index=0xffff Seq=2 | ...payload |
  +----------------------------+------------+

Tunneling Considerations
------------------------

The SIG only tunnels unicast IPv4 and IPv6 traffic. Multicast traffic is not supported.

In accordance with `RFC 8085 <https://www.rfc-editor.org/rfc/rfc8085>`_ (UDP Usage Guidelines), IP-based unicast traffic is assumed to be congestion controlled at the transport layer by the original sender. The SIG tunnel therefore does not implement its own congestion control mechanisms for the encapsulated payload.

Operational Guide
=================

For deployment, configuration, and operational information about the SIG, see the :doc:`/manuals/gateway`.
