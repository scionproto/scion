**************************
Cryptographic Interactions
**************************

The main purpose of the SCION control plane PKI is to provide a mechanism to to
distribute and authenticate public keys that are used to verify control plane
messages and information. For example the SCION path segments are signed with
keys that are authenticated through the SCION CP-PKI.

In this document, we describe the cryptographic interactions between control
plane entities. I.e., how certificates are distributed, and how they are used
to verify messages and establish secret and authentic channels.

AS certificate use cases
========================

Currently, we have two use cases: authenticating control plane messages, and
establishing a secure channel. The basis for both of these use cases is the AS
certificate. We discuss these use cases briefly and go into detail, how the
relying parties get the required cryptographic material.

Authentic control plane messages
--------------------------------

In SCION, most control plane messages are signed. For example, each AS hop
information in path segment is signed by the respective AS. All relying parties
are able to verify the signatures with the help of the CP-PKI.

Signing process
^^^^^^^^^^^^^^^

To sign a message, the signing entity chooses an AS certificate that
authenticates their private key. With the private key, they sign the message and
attach the following information as signature metadata:

- ISD-AS: The ISD-AS number of the signing entity.
- Subject Key Identifier: The key identifier of the public key used to verify the
  message.

This is the bare minimum information a relying party requires to identify which
certificate to use to verify the signed message.

Additionally, the signer should include the following information:

- Serial and base number of the latest TRC: Including this information allows
  relying parties to discover TRC updates and trust resets passively without
  actively querying the authoritative ASes in the respective ISDs.
- Timestamp: For many messages, the timestamp is useful information to ensure
  recentness of the message.

Verifying process
^^^^^^^^^^^^^^^^^

When the relying party gets a message that they want to verify, they first need
to identify the certificate that authenticates the corresponding public key.

AS certificates are bundled together with the CA certificate that signed them
into certificate chains. For efficiency, these certificate chains are
distributed decoupled from the signed messages. A certificate chain is verified
against a root certificate. However, the root certificate is not bundled in the
chain, it is bundled in the TRC. This allows TRC updates that extend the
validity period of the root certificate without the need to modify the
certificate chain.

Now, to verify, the relying party first builds a collection of the root
certificates from the latest TRC from the ISD referenced in the signature
metadata. If the grace period introduced by the latest TRC is still on-going,
the root certificates in the second to latest TRC are also included. For more
detailed instruction, see :ref:`trc-selection`. If the signature metadata
contains the serial and base number, the relying part checks that they have at
least that TRC or a newer one available.

After the relying party has constructed the pool of root certificates, they have
to select a certificate chain that can be used to verify the message. To do so,
they select a certificate chain with an AS certificate that has the following
properties:

- The ISD-AS in the subject of the AS certificate matches the ISD-AS in the
  signature metadata.
- The Subject Key Identifier of the AS certificate matches the Subject Key
  Identifier in the signature metadata.
- The AS certificate is valid at verification time. Normally, this will be the
  current time. In special cases, e.g., auditing the time can be set to the past
  to check if the message was verifiable at the given time.

The relying party executes the regular X509 verification path to verify the
messages against the set of root certificates. In addition, the relying party
checks that all subjects carry the same ISD number, that each certificate is of
valid type, i.e., that the AS certificate is indeed a valid AS certificate, and
that the CA certificate validity period covers the AS certificate validity period.

If any crypto material is missing in the process, the relying party queries the
originator of the message for the missing material. If it can not be resolved,
the verification process fails.

An implication of this is that path segments should be checked whether they are
verifiable at time of use. We cannot simply rely on them being verified on
insert, since TRC updates that change the root key can invalidate a certificate
chain.

Secret and authentic channel
----------------------------

In SCION, some control plane interactions require a secret and authentic
channel. For example, the DRKey and hidden path exchange require such a channel.
With the X509v3 certificates, we can profit from the existing TLS protocol
to establish a secret and authentic connection.

When establishing a TLS connection, both the client and the server provide their
certificate chain. The AS certificate for the client side must have the extended
key purpose ``id-kp-clientAuth``. The AS certificate for the server side must
have the extended key purpose ``id-kp-serverAuth`` set.

The certificates are verified against the root certificates authenticated by the
latest available TRC.

.. note::

   A caveat of this is, that if the other side does not notice a TRC update, it
   might not be able to verify the certificate chain. We will tackle this issue
   when we gat to implementing this mechanism. One solution could be, to encode
   information about the latest TRC inside the exchanged certificate chains.

TRC update discovery
====================

Relying parties need to have recent TRCs available. They should notice TRC
updates in a reasonable time frame. There are multiple mechanisms for how a
relying party notices these updates.

Beaconing process
-----------------

The TRC version is announced in the beaconing process. Each AS announces what it
considers to be the latest TRC. Furthermore, each AS includes the digest of the
TRC contents to allow discovering discrepancies.

Thus, relying parties that are part of the beaconing process notice TRC updates
passively. I.e., the control service in a core AS notices TRC updates for remote
ISDs that are on the beaconing path. The control service in a non-core AS only
notices TRC updates for the local ISD through the beaconing process.

Path resolution
---------------

In every path segment, all ASes reference the latest TRC of their ISD. Thus,
when resolving paths, every relying party notices TRC updates even remote ones.
This mechanism only works for ISDs that the relying party actively communicates
with.

Active discovery
----------------

Relying parties actively query authoritative ASes in the ISDs they want to have
recent TRCs.

Messages
========

To enable the interactions mentioned above, the following messages are necessary:

- Specific certificate chain:

  .. code-block:: text

     Query: ISD-AS, Subject Key ID, time period
     Response: Set of certificate chains

  The requester asks for certificate chains that match the query. A certificate
  chain matches the query, if the AS certificate's subject contains the ISD-AS,
  the AS certificate's subject key identifier matches, and the validity period
  of the AS certificate covers the follow queried time period.

- Specific TRC:

  .. code-block:: text

     Query: ISD, serial number, base number
     Response: signed TRC

  The requester asks for a TRC that matches the query. I.e, a TRC that carries
  exactly the values that of the query.

- Latest TRC:

  .. code-block:: text

     Query: ISD
     Response: ISD, serial number, base number, signature

  The requester asks what the latest TRC for a given ISD known to the requestee
  is. The response is signed by the requestee, to ensure answers cannot be
  modified by a third party.
  Only authoritative ASes are required to respond to these requests.

For automatic certificate renewal the following messages are necessary:

- Certificate renewal request:

  .. code-block:: text

     Query: CSR, signature
     Response: renewed certificate chain

  The requester sends the CSR and a signature over the CSR to its CA. The CA
  must have a mechanism to verify the signature. As a base protocol, we propose
  that the signature must be verifiable with a still active AS certificate for
  the subject issued by the CA itself. The response is the renewed certificate
  chain.
  Only CA ASes are required to respond to these requests.

- Certificate chain push:

  .. code-block:: text

     Query: set of certificate chains
     Response: ack

  The CA ASes are required to eventually register the issued certificate chains
  with the authoritative ASes. With this message the CA ASes can push the new
  certificate chains to all authoritative ASes.
