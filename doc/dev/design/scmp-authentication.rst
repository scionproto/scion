*******************
SCMP Authentication
*******************

- Author(s): Matthias Frei
- Last updated: 2024-05-23
- Discussion at: :issue:`3969`
- Status: **Postponed**

Reason for postponment: no clear consensus that this is the right approach. See "Discussion" section.
Experimental support in router, added in :issue:`4255`.

Abstract
========
:doc:`SCMP </protocols/scmp>` error messages can potentially be abused by an attacker to signal spurious network errors, attempting to degrade or deny a victim's use of a service or network path.
Employ cryptographic validation to check authenticity and authorization of the sender of an SCMP message.

Background
==========

SCMP error messages can potentially be abused by an attacker to signal spurious network errors.
Implementations of TCP/IP, face a similar challenge with ICMP error messages; in order to avoid acting on fraudulent errors, they carefully validate ICMP messages using their internal state machine and ignore errors that appear unlikely to happen e.g. after the connection has already been established RFC 5927.
QUIC goes even further and simply ignores all ICMP errors, except those related to MTU discovery.

This approach can only mitigate the problem.
Furthermore, this approach is not sufficient in SCION as the applications/transport layer on end hosts are expected to react to events in the network, e.g. path failures, by changing to a different path.
The occurrence of such events is independent of the transport's internal state machine.
This aspect does not exist in IP based internet, where the network will transparently adapt the routing (or not) on faults.

To address this, we use :doc:`/cryptography/drkey` and the :doc:`/protocols/authenticator-option` to authenticate SCMP messages.

Proposal
========

As noted in the :doc:`/protocols/scmp`, support for the SCMP protocol is optional for SCION nodes.
This proposal *mandates* authentication for most SCMP messages.
Should this proposal be adopted, it extends the SCMP specification, and terms MUST/MUST NOT/MAY used below will apply to all SCION nodes with an SCMP implementations.
In other words, SCION nodes either need to implement the additional processing rules for SCMP messages described in this document, or remove SCMP support altogether.

.. _scmp-spao:

SCMP with SCION Packet Authenticator Option
-------------------------------------------

SCMP messages can be authenticated with a MAC based on a symmetric key established with the :ref:`DRKey infrastructure <drkey>`.
The MAC is transported in the :ref:`authenticator-option` End-to-End extension header.

The Authenticator MAC algorithm is AES-CMAC (identifier :code:`0`).

SCMP error messages MUST always be authenticated.
SCMP informational messages MAY optionally be authenticated; a response message
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
The processing rules for SCMP messages are extended with the following points:

-  Every SCMP error message MUST be authenticated.

   Every SCMP informational reply message MUST be authenticated if and only if
   the corresponding request was authenticated.

   .. note::
      Consequentially, an implementation without support for SCMP
      authentication MUST never send SCMP error messages and MUST NOT reply to
      authenticated SCMP informational request messages.

-  When an SCMP message is received, the receiver MUST check the
   authentication header.

   - SCMP error messages without or with an invalid authentication header and
     SCMP informational messages with an invalid authentication header MUST
     be silently dropped.

   - The receiver checks that the :ref:`DRKey identified by the SPI <spao-spi-drkey>`
     is appropriate for the SCMP message type and code, as described above in
     the section :ref:`scmp-spao`.

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

Compatibility
=============
As SCMP authentication is a new addition, there will be a transition period during which receivers
may accept SCMP error messages without authentication.

Discussion
==========

Even though this proposal had been accepted, it later turned out that there is no strong consensus
to implement this in all routers and end points. For now, this has been put on hold.
Alternative options that can be considered:

- No authentication, expand the heuristics that end hosts apply to detect fraudulent SCMP messages.
- Authenticate only :ref:`external-interface-down` and :ref:`internal-connectivity-down` messages.
  If we authenticate only the information about the link that is down (ISD, AS, interface IDs) and a coarse timestamp, we can reuse the same signed message body for link down notifications for some time period, e.g. a few seconds.
  Protection against message replay is not a concern for these messages types, as receivers can naturally consider them less and less relevant the longer ago they were created.
  This allows authenticating these message body with relatively slow asymmetric cryptographic signatures with the CP-PKI, removing the dependency on DRKey.
  The signature would be part of the SCMP message format for these specific messages and thus no longer requires the SPAO header.
  Overall, this approach is very similar to the "Path revocation" messages that we historically used to have.
