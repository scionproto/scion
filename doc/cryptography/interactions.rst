**************************
Cryptographic Interactions
**************************

The main purpose of the SCION control plane PKI is to distribute and authenticate
the public keys used to verify control plane messages and information. For example,
SCION path segments are signed with keys that are authenticated through the CP-PKI.

These interactions cover how certificates are distributed, how they are used to
verify messages, and how they establish secret and authentic channels. The
normative specification of these operations is in `CP-PKI Operations
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-cp-pki-operations>`_.

AS certificate use cases
========================

There are two use cases, both rooted in the AS certificate: authenticating control
plane messages, and establishing a secure channel.

Authentic control plane messages
--------------------------------

Most SCION control plane messages (for example, each AS's hop information in a path
segment) are signed, and any relying party can verify them via the CP-PKI. The
signer attaches signature metadata — at minimum the ISD-AS and the Subject Key
Identifier of the signing key, and typically the latest TRC's serial/base number
and a timestamp. To verify, the relying party locates the AS certificate chain
matching that metadata, builds the trust-anchor root pool from the relevant TRC(s),
and runs the regular X.509 path verification, checking that the certificate is
valid at verification time. The signing and verification procedures are specified
in `Signing and Verifying Control Plane Messages
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-signing-and-verifying-contr>`_.

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

Relying parties must keep recent TRCs available and need to notice TRC updates in
a reasonable time frame. Updates are discovered passively through the beaconing
process and through path resolution (every AS references its latest TRC in path
segments), and actively by querying authoritative ASes. These discovery mechanisms
are specified in `TRC Update Discovery
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-trc-update-discovery>`_.

Messages
========

.. note::

   The wire formats of the queries and responses below are not specified here.
   They are defined by the SCION control plane specification; see `Distribution of
   Cryptographic Material
   <https://scionassociation.github.io/scion-cp_I-D/draft-dekater-scion-controlplane.html#name-distribution-of-cryptograph>`_.

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
