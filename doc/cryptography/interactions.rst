**************************
Cryptographic Interactions
**************************

The main purpose of the SCION control plane PKI is to distribute and authenticate
the public keys used to verify control plane messages and information. For example,
SCION path segments are signed with keys that are authenticated through the CP-PKI.

These interactions cover how certificates are distributed, how they are used to
verify messages, and how they establish secret and authentic channels.
The normative specification of these operations is in `CP-PKI Operations
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-cp-pki-operations>`_.

AS certificate use cases
========================

There are two use cases, both rooted in the AS certificate: authenticating control
plane messages, and establishing a secure channel.

Authentic control plane messages
--------------------------------

An AS uses the private key of its AS certificate to sign the parts of its
control plane messages that relying parties must authenticate. Each AS entry
in a path segment carries a signature and signature metadata: the ISD-AS,
the signing key's Subject Key Identifier, the latest TRC's base and serial
numbers, and an optional timestamp. The relying party builds the root
certificate pool from the latest TRC of the ISD in the metadata and, during
that TRC's grace period, from its predecessor. If the metadata references a TRC
the relying party has not seen, it fetches that TRC. It selects the certificate
chain whose AS certificate matches the ISD-AS and Subject Key Identifier and
is valid at the verification time. It runs X.509 path verification plus the
SCION checks on ISD numbers, certificate types and validity periods, then
verifies the signature with the AS certificate's public key.
`Signing and Verifying Control Plane Messages
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-signing-and-verifying-contr>`_
specifies the signing and verification procedures.

When an AS renews its certificate over the control plane, the request carries
two signatures. The AS signs the PKCS #10 CSR with the new private key (proof
of possession). It signs the CMS SignedData that wraps the CSR with the private
key of one of its currently valid AS certificates (authorization). The response
carries a CMS SignedData with the new AS certificate followed by the CA certificate.
`Issuing Control Plane AS Certificates
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-issuing-control-plane-as-ce>`_
specifies the signatures. `Renewal of Cryptographic Material
<https://www.ietf.org/archive/id/draft-dekater-scion-controlplane-18.html#name-renewal-of-cryptographic-ma>`_
specifies the messages.

In the `open-source SCION implementation <https://github.com/scionproto/scion>`__,
the ``certificates`` field of the request's CMS SignedData must hold exactly the
requester's AS certificate and CA certificate. The CA verifies this chain against
the latest TRC of the requester's ISD or, during that TRC's grace period,
against its predecessor.

The `trust material messages
<https://www.ietf.org/archive/id/draft-dekater-scion-controlplane-18.html#name-distribution-of-cryptograph>`_
(``ChainsRequest``, ``ChainsResponse``, ``TRCRequest`` and ``TRCResponse``) are
not signed. The certificate chains they return verify against the root
certificates in the TRC, and each TRC carries its own CMS signatures.

Secret and authentic channel
----------------------------

In SCION, some control plane interactions require a secret and authentic channel.
For example, the DRKey and hidden path exchange require such a channel.
With the X509v3 certificates, we can profit from the existing TLS protocol
to establish a secret and authentic connection.

When establishing a TLS connection, both the client and the server provide their
certificate chain. The AS certificate for the client side must have the extended
key purpose ``id-kp-clientAuth``. The AS certificate for the server side must
have the extended key purpose ``id-kp-serverAuth`` set.

The certificates are verified against the root certificates authenticated by the
latest available TRC.

TRC update discovery
====================

Relying parties must keep recent TRCs available and need to notice TRC updates in
a reasonable time frame. Updates are discovered passively through the beaconing
process and through path resolution (every AS references its latest TRC in path segments),
and actively by querying authoritative ASes.
These discovery mechanisms are specified in `TRC Update Discovery
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-trc-update-discovery>`_.
In the open-source SCION implementation, a ``TRCRequest`` with base and serial
number 0 returns the latest TRC that the control service stores for the ISD.
