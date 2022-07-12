.. _scmp-specification:

******************
SCMP Specification
******************

.. |br| raw:: html

  <br/>

This document contains the specification for the SCION Control Message Protocol.

Introduction
============

The SCION Control Message Protocol (SCMP) is analogous to the Internet Control
Message Protocol (ICMP). It provides functionality for network diagnostics, such
as ping and traceroute, and error messages that signal packet processing or
network-layer problems. SCMP is an integral part of SCION, and as such, all
messages and behavior required by this specification MUST be fully implemented
by every SCION node.

General Format
==============

Every SCMP message is preceded by a SCION header, and zero or more SCION
extension headers. The SCMP header is identified by a ``NextHdr`` value of ``1``
in the immediately preceding header.

The messages have the following general format::

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            InfoBlock                          |
    +                                                               +
    |                         (variable length)                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            DataBlock                          |
    +                                                               +
    |                         (variable length)                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


- The ``Type`` field indicates the type of SCMP message. Its value determines
  the format of the info and data block.

- The ``Code`` provides additional granularity to the SCMP type.

- The ``Checksum`` field is used to detect data corruption.

- The ``InfoBlock`` is an optional field of variable length. The format is
  dependent on the message type.

- The ``DataBlock`` is an optional field of variable length. The format is
  dependent on the message type.

Types
-----

SCMP messages are grouped into two classes: error messages and informational
messages. Error messages are identified by a zero in the high-order bit of the
type value. I.e., error messages have a type value in the range of 0-127.
Informational messages have type values in the range of 128-255.

This specification defines the message formats for the following SCMP messages:

**SCMP error messages**:

==== ==============================================================
Type Meaning
==== ==============================================================
1    :ref:`Destination Unreachable <destination-unreachable>`
2    :ref:`Packet Too Big <packet-too-big>`
3    (not assigned)
4    :ref:`Parameter Problem <parameter-problem>`
5    :ref:`External Interface Down <external-interface-down>`
6    :ref:`Internal Connectivity Down <internal-connectivity-down>`

100  Private Experimentation
101  Private Experimentation

127  Reserved for expansion of SCMP error messages
==== ==============================================================

**SCMP informational messages**:

==== ==============================================================
Type Meaning
==== ==============================================================
128  :ref:`Echo Request <echo-request>`
129  :ref:`Echo Reply <echo-reply>`
130  :ref:`Traceroute Request <traceroute-request>`
131  :ref:`Traceroute Reply <traceroute-reply>`

200  Private Experimentation
201  Private Experimentation

255  Reserved for expansion of SCMP informational messages
==== ==============================================================

Type values 100, 101, 200, and 201 are reserved for private experimentation.
They are not intended for general use. Any wide-scale and/or uncontrolled usage
should obtain a real allocation.

Type values 127 and 255 are reserved for future expansion of in case of a
shortage of type values.

Checksum Calculation
--------------------

The checksum is the 16-bit one's complement of the one's complement sum of the
entire SCMP message, starting with the SCMP message type field, and prepended
with a "pseudo-header" consisting of the SCION address header and the layer-4
protocol type as defined in :ref:`pseudo-header-upper-layer-checksum`.

.. _scmp-authentication:

Authentication
--------------
SCMP messages can be authenticated with a MAC based on a symmetric key
established with the :ref:`DRKey infrastructure <drkey>`.
The MAC is transported in the :ref:`authenticator-option` End-to-End extension
header.

The Authenticator MAC algorithm is AES-CMAC (identifier :code:`0`).

SCMP error messages MUST always be authenticated.
SCMP informational messages CAN optionally be authenticated; a response message
MUST be authenticated if and only if the corresponding request message was
authenticated.

All DRKey keys used here are derived with :ref:`protocol identifier <drkey-protocol-identifiers>` :code:`SCMP`, decimal :code:`1`.

SCMP messages from (and to) routers are authenticated with :ref:`AS-host keys <drkey-as-host>`.
SCMP response messages from a router in AS :math:`D` to a node :math:`H_s` in
AS :math:`S` are authenticated with the DRKey :math:`K_{D,S:H_s}`.
SCMP requests (specifically, :ref:`traceroute-request`) processed by a router
are authenticated with the same key.

SCMP messages between two end-hosts are authenticated with :ref:`host-host keys <drkey-host-host>`.
An SCMP response message from a node :math:`H_d` in AS :math:`D` to a node
:math:`H_s` in AS :math:`S` is authenticated with the key
:math:`K_{D:H_d,S:H_s}`.
SCMP requests and data packets from :math:`H_s` to :math:`H_d` are
authenticated with this same key.

For packets addressed to a router directly (specifically for
:ref:`echo-request` and :ref:`echo-reply`) it is treated like an end-host and
the corresponding host-host keys are used.

.. note::
   Recall that :ref:`traceroute-request`\s are *not* addressed to the router.
   Instead, the router processes the request if its router alert flag is set.


Processing Rules
----------------

Implementations MUST respect the following rules when processing SCMP messages:

#. If an SCMP error message of unknown type is received at its destination, it
   MUST be passed to the upper-layer process that originated the packet that
   caused the error, if it can be identified.

#. If an SCMP informational message of unknown type is received, it MUST be
   silently dropped.

#. Every SCMP error message MUST include as much of the offending SCION packet
   as possible without making the error message packet - including the SCION
   header and all extension headers - exceed **1232 bytes**.

#. In case the implementation is required to pass an SCMP error message to the
   upper-layer process, the upper-layer protocol type is extracted from the
   original packet in the body of the SCMP error message and used to select the
   appropriate process to handle the error.

   In case the upper-layer protocol type cannot be extracted from the SCMP error
   message body, the SCMP message MUST be silently dropped.

#. In SCMP error message MUST NOT be originated in response of receiving any of
   the following:

   #. A SCMP error message

   #. A packet whose source address does not uniquely identify a single node.
      E.g., an IPv4 or IPv6 multicast address.

#. Every SCMP error message MUST be authenticated.

   Every SCMP informational reply message MUST be authenticated if and only if
   the corresponding request was authenticated.

   .. note::
      Consequentially, an implementation without support for SCMP
      authentication MUST never send SCMP error messages and MUST NOT reply to
      authenticated SCMP informational request messages.

#. When an SCMP message is received, the receiver SHOULD check the
   authentication header.

   - SCMP error messages without or with an invalid authentication header and
     SCMP informational messages with an invalid authentication header SHOULD
     be silently dropped.

     .. note::
        As SCMP authentication is a new addition, there will be a transition period
        during which receivers may accept SCMP error messages without authentication.

   - The receiver checks that the :ref:`DRKey identified by the SPI <spao-spi-drkey>`
     is appropriate for the SCMP message type and code, as described above in
     the :ref:`section Authentication <scmp-authentication>`.

   - The receiver derives or fetches the relevant key for validation of the MAC.

   - Before checking the authentication, and in particular before fetching a
     key, the receiver SHOULD check whether the quoted message was possibly
     recently sent via/to the originator of the error message.

   - The receiver MUST limit the traffic to the control service to fetch keys
     for verifying the authentication of an SCMP message.
     At most one packet SHOULD be sent to fetch the key for a received SCMP
     message. If this fails or is not possible (e.g. because there is no
     existing TCP session to the control service), the message SHOULD be
     silently dropped.


SCMP Error Messages
===================

.. _destination-unreachable:

Destination Unreachable
-----------------------

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                             Unused                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                As much of the offending packet                |
    +              as possible without the SCMP packet              +
    |                    exceeding 1232 bytes.                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+--------------+---------------------------------------------------------------+
| SCMP Fields                                                                  |
+==============+===============================================================+
| Type         | 1                                                             |
+--------------+---------------------------------------------------------------+
| Code         | 0 - No route to destination                               |br||
|              | 1 - Communication administratively denied                 |br||
|              | 2 - Beyond scope of source address                        |br||
|              | 3 - Address unreachable                                   |br||
|              | 4 - Port unreachable                                      |br||
|              | 5 - Source address failed ingress/egress policy           |br||
|              | 6 - Reject route to destination                           |br||
+--------------+---------------------------------------------------------------+
| Unused       | Initialized to zero by originator and ignored by the receiver.|
+--------------+---------------------------------------------------------------+

A **Destination Unreachable** message SHOULD be generated in the originating
node in response to a packet that cannot be delivered to its destination address
for reasons other than congestion. This type of error message MUST only be
originated by nodes in the destination AS of the offending packet. In particular,
issues with a packet's path header do not spawn this error message.

If the reason for the failure to deliver is lack of a matching entry in the
forwarding node's routing table, the code is set to 0.

If the reason for the failure to deliver is administrative prohibition, the code
is set to 1.

If the reason for failure to deliver is that the destination is beyond the scope
of the source address, the code is set to 2.

If the reason for the failure to deliver cannot be mapped to any of the other
codes, the code is set to 3.

If a destination node has no listener for the transport protocol, it SHOULD
originate a Destination Unreachable message with code 4, if the protocol has no
alternative means of informing the sender.

If the reason for the failure to deliver is that the packet with this source
address is not allowed due to ingress/egress filtering policies, the code is 5.

If the reason for the failure to deliver is that the route is rejected, the code
is set to 6.

Codes 5 and 6 are more granular subsets of code 1.

Implementations SHOULD allow disabling origination of Destination Unreachable
messages for security reasons.

.. _packet-too-big:

Packet Too Big
--------------

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            reserved           |             MTU               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                As much of the offending packet                |
    +              as possible without the SCMP packet              +
    |                    exceeding 1232 bytes.                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+--------------+---------------------------------------------------------------+
| SCMP Fields                                                                  |
+==============+===============================================================+
| Type         | 2                                                             |
+--------------+---------------------------------------------------------------+
| Code         | 0                                                             |
+--------------+---------------------------------------------------------------+
| MTU          | The Maximum Transmission Unit of the next-hop link.           |
+--------------+---------------------------------------------------------------+

A **Packet Too Big** message MUST be originated by a router in response to a
packet that cannot be forwarded because the packet is larger than the MTU of the
outgoing link. The MTU value is set to the maximum size a SCION packet can have
to still fit on the next-hop link, as the sender has no knowledge of the
underlay.

.. _parameter-problem:

Parameter Problem
-----------------

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            reserved           |           Pointer             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                As much of the offending packet                |
    +              as possible without the SCMP packet              +
    |                    exceeding 1232 bytes.                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+--------------+---------------------------------------------------------------+
| SCMP Fields                                                                  |
+==============+===============================================================+
| Type         | 4                                                             |
+--------------+---------------------------------------------------------------+
| Code         | 0 - Erroneous header field                                |br||
|              | 1 - Unknown NextHdr type                                  |br||
|              | 2 - (unassigned)                                          |br||
|              |                                                               |
|              | 16 - Invalid common header                                |br||
|              | 17 - Unknown SCION version                                |br||
|              | 18 - FlowID required                                      |br||
|              | 19 - Invalid packet size                                  |br||
|              | 20 - Unknown path type                                    |br||
|              | 21 - Unknown address format                               |br||
|              |                                                               |
|              | 32 - Invalid address header                               |br||
|              | 33 - Invalid source address                               |br||
|              | 34 - Invalid destination address                          |br||
|              | 35 - Non-local delivery                                   |br||
|              |                                                               |
|              | 48 - Invalid path                                         |br||
|              | 49 - Unknown hop field cons ingress interface             |br||
|              | 50 - Unknown hop field cons egress interface              |br||
|              | 51 - Invalid hop field MAC                                |br||
|              | 52 - Path expired                                         |br||
|              | 53 - Invalid segment change                               |br||
|              |                                                               |
|              | 64 - Invalid extension header                             |br||
|              | 65 - Unknown hop-by-hop option                            |br||
|              | 66 - Unknown end-to-end option                            |br||
+--------------+---------------------------------------------------------------+
| Pointer      | Byte offset in the offending packet where the error was       |
|              | detected. Can point beyond the end of the SCMP packet if the  |
|              | offending byte is in the part of the original packet that     |
|              | does not fit in the data block.                               |
+--------------+---------------------------------------------------------------+

If a node processing a packet finds a problem with a field in the SCION common
header, the path header, or SCION extensions headers such that it cannot
complete processing the packet, it MUST discard the packet and SHOULD originate
a **Parameter Problem** message indicating the type and location of the problem.

The pointer identifies the offending byte of the original packet where the error
was detected.

The codes are structured hierarchically. At the top is code 0 that catches
all errors of this type. All other codes are a more granular description of the
error.

Codes 16-21 describe problems related to the common header. 17-21 are more
granular subsets of 16.

Codes 32-35 describe problems related to the address header. 33-35 are more
granular subsets of 32.

A **Parameter Problem** error message with code 35 SHOULD be originated in
response to a packet that is on the last hop of its path, but the destination
ISD-AS does not match the local ISD-AS.

Codes 48-53 describe problems related to the path header. 49-53 are more
granular subsets of 48.

Codes 64-66 describe problems related to extension headers. 65-66 are more
granular subsets of 64.

.. _external-interface-down:

External Interface Down
-----------------------

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              ISD              |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                        Interface ID                           +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                As much of the offending packet                |
    +              as possible without the SCMP packet              +
    |                    exceeding 1232 bytes.                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+--------------+---------------------------------------------------------------+
| SCMP Fields                                                                  |
+==============+===============================================================+
| Type         | 5                                                             |
+--------------+---------------------------------------------------------------+
| Code         | 0                                                             |
+--------------+---------------------------------------------------------------+
| ISD          | The 16-bit ISD identifier of the SCMP originator              |
+--------------+---------------------------------------------------------------+
| AS           | The 48-bit AS identifier of the SCMP originator               |
+--------------+---------------------------------------------------------------+
| Interface ID | The interface ID of the external link with connectivity issue.|
+--------------+---------------------------------------------------------------+

A **External Interface Down** message MUST be originated by a router in response
to a packet that cannot be forwarded because the link to an external AS broken.
The ISD and AS identifier are set to the ISD-AS of the originating router.
The interface ID identifies the link of the originating AS that is down.

Recipients can use this information to route around broken data-plane links.

.. _internal-connectivity-down:

Internal Connectivity Down
--------------------------

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              ISD              |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                   Ingress Interface ID                        +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                   Egress Interface ID                         +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                As much of the offending packet                |
    +              as possible without the SCMP packet              +
    |                    exceeding 1232 bytes.                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+--------------+---------------------------------------------------------------+
| SCMP Fields                                                                  |
+==============+===============================================================+
| Type         | 6                                                             |
+--------------+---------------------------------------------------------------+
| Code         | 0                                                             |
+--------------+---------------------------------------------------------------+
| ISD          | The 16-bit ISD identifier of the SCMP originator              |
+--------------+---------------------------------------------------------------+
| AS           | The 48-bit AS identifier of the SCMP originator               |
+--------------+---------------------------------------------------------------+
| Ingress ID   | The interface ID of the ingress link.                         |
+--------------+---------------------------------------------------------------+
| Egress ID    | The interface ID of the egress link.                          |
+--------------+---------------------------------------------------------------+

A **Internal Connectivity Down** message MUST be originated by a router in
response to a packet that cannot be forwarded inside the AS because because the
connectivity between the ingress and egress routers is broken. The ISD and AS
identifier are set to the ISD-AS of the originating router. The ingress
interface ID identifies the interface on which the packet enters the AS. The
egress interface ID identifies the interface on which the packet is destined to
leave the AS, but the connection is broken to.

Recipients can use this information to route around broken data-plane inside an
AS.

SCMP Informational Messages
===========================

.. _echo-request:

Echo Request
------------

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Data...
    +-+-+-+-+-

+--------------+---------------------------------------------------------------+
| SCMP Fields                                                                  |
+==============+===============================================================+
| Type         | 128                                                           |
+--------------+---------------------------------------------------------------+
| Code         | 0                                                             |
+--------------+---------------------------------------------------------------+
| Identifier   | A 16-bit identifier to aid matching replies with requests     |
+--------------+---------------------------------------------------------------+
| Sequence Nr. | A 16-bit sequence number to aid matching replies with requests|
+--------------+---------------------------------------------------------------+
| Data         | Variable length of arbitrary data                             |
+--------------+---------------------------------------------------------------+

Every node MUST implement a SCMP Echo responder function that receives Echo
Requests and originates corresponding Echo replies.

.. _echo-reply:

Echo Reply
------------

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Data...
    +-+-+-+-+-

+--------------+---------------------------------------------------------------+
| SCMP Fields                                                                  |
+==============+===============================================================+
| Type         | 129                                                           |
+--------------+---------------------------------------------------------------+
| Code         | 0                                                             |
+--------------+---------------------------------------------------------------+
| Identifier   | The identifier of the Echo Request                            |
+--------------+---------------------------------------------------------------+
| Sequence Nr. | The sequence number of the Echo Request                       |
+--------------+---------------------------------------------------------------+
| Data         | The data of the Echo Request                                  |
+--------------+---------------------------------------------------------------+

Every node MUST implement a SCMP Echo responder function that receives Echo
Requests and originates corresponding Echo replies.

The data received in the SCMP Echo Request message MUST be returned entirely and
unmodified in the SCMP Echo Reply message.

.. _traceroute-request:

Traceroute Request
------------------

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              ISD              |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                          Interface ID                         +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+--------------+---------------------------------------------------------------+
| SCMP Fields                                                                  |
+==============+===============================================================+
| Type         | 130                                                           |
+--------------+---------------------------------------------------------------+
| Code         | 0                                                             |
+--------------+---------------------------------------------------------------+
| Identifier   | A 16-bit identifier to aid matching replies with requests     |
+--------------+---------------------------------------------------------------+
| Sequence Nr. | A 16-bit sequence number to aid matching replies with request |
+--------------+---------------------------------------------------------------+
| ISD          | Place holder set to zero by SCMP sender                       |
+--------------+---------------------------------------------------------------+
| AS           | Place holder set to zero by SCMP sender                       |
+--------------+---------------------------------------------------------------+
| Interface ID | Place holder set to zero by SCMP sender                       |
+--------------+---------------------------------------------------------------+

The border router is alerted of the Traceroute Request message through the
ConsIngress or ConsEgress Router Alert flag in the hop field. Senders have to
set them appropriately.

.. _traceroute-reply:

Traceroute Reply
------------------

.. code-block:: text

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     Type      |     Code      |          Checksum             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           Identifier          |        Sequence Number        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              ISD              |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         AS                    +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                          Interface ID                         +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

+--------------+---------------------------------------------------------------+
| SCMP Fields                                                                  |
+==============+===============================================================+
| Type         | 131                                                           |
+--------------+---------------------------------------------------------------+
| Code         | 0                                                             |
+--------------+---------------------------------------------------------------+
| Identifier   | The identifier set in the Traceroute Request                  |
+--------------+---------------------------------------------------------------+
| Sequence Nr. | The sequence number of the Tracroute Request                  |
+--------------+---------------------------------------------------------------+
| ISD          | The 16-bit ISD identifier of the SCMP originator              |
+--------------+---------------------------------------------------------------+
| AS           | The 48-bit AS identifier of the SCMP originator               |
+--------------+---------------------------------------------------------------+
| Interface ID | The interface ID of the SCMP originating router               |
+--------------+---------------------------------------------------------------+

The border router is alerted of the Traceroute Request message through the
ConsIngress or ConsEgress Router Alert flag in the hop field. When such a packet
is received, the border router **MUST** reply with a Traceroute Reply message.

The identifier is set to the value of the Traceroute Request message. The ISD
and AS identifiers are set to the ISD-AS of the originating border router.

