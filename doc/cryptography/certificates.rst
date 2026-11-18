*************************
Certificates
*************************

.. highlight:: text

SCION uses three types of X.509 v3 **Control Plane (CP) certificates** that build
on top of [RFC5280]_ (which in turn builds on [X509]_), adding more restrictive
SCION-specific constraints:

- .. _cp-root-certificate:

  `CP Root Certificates
  <https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-control-plane-root-certific>`_
  determine which ASes act as issuing CAs in an ISD. They are self-signed CA
  certificates. TRCs embed them as the start of the verification path (see the
  :doc:`TRC Specification <trc>`). Their extended key usage includes
  ``id-kp-root``, and their basic constraints set ``cA`` TRUE and
  ``pathLenConstraint`` 1.
- .. _cp-ca-certificate:

  `CP Issuing CA Certificates
  <https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-control-plane-issuing-ca-ce>`_
  are CA certificates signed by **CP Root Certificates**. CA ASes use them to
  sign **CP AS Certificates**. Their basic constraints set ``cA`` TRUE and
  ``pathLenConstraint`` 0.
- .. _cp-as-certificate:

  `CP AS Certificates
  <https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-control-plane-as-certificat>`_
  are end-entity certificates. They hold the public key that verifies the
  control plane messages an AS signs. Their key usage includes
  ``digitalSignature``. Their extended key usage includes
  ``id-kp-timeStamping``, plus ``id-kp-serverAuth`` or ``id-kp-clientAuth`` on
  the server or client side of a CP TLS session.

Additionally, SCION uses two **voting certificates**: the *sensitive voting
certificate* and the *regular voting certificate*, which carry the keys that cast
votes in the TRC update process (see the :doc:`TRC Specification <trc>`).

The control plane PKI has no certificate revocation. Instead, it relies on
short-lived certificates, TRC updates and trust resets (see `Substitutes to
Certificate Revocation
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#substitutes-to-revocation>`_).
Each certificate type has a `recommended maximum validity
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#table-2>`_.

The full normative specification including the certificate fields, per-type profiles,
extensions, and the ASN.1 syntax is defined in the `SCION PKI draft
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html>`_.

This document assumes a trusted set of **CP Root Certificates** already exists.
How such a set is selected is described in the :doc:`TRC Specification <trc>`.

.. _general-certificate-requirements:

General certificate requirements
================================

SCION CP certificates are X.509 v3 certificates (the ``version`` field is always
``v3``, since ``extensions`` are mandatory). Every certificate has a ``subject``
and an ``issuer``, which are the same entity for self-signed and self-issued
certificates. The detailed requirements for the ``version``, ``serialNumber``,
``signature``, ``issuer``, ``validity``, ``subject``, ``subjectPublicKeyInfo`` and
``extensions`` fields are given in `X.509 Certificate Profiles and Constraints
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-x509-certificate-profiles-a>`_.
These requirements specify which [RFC5280]_/[X509]_ options SCION forbids or
constrains.

.. _certificate-signature:

Signature
---------

For security reasons, SCION uses a custom list of acceptable algorithms.
The accepted algorithms and curves are listed in the `Signature field
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-signature>`_
section of the SCION PKI draft.

The `open-source SCION implementation <https://github.com/scionproto/scion>`__
supports three mandatory *ECDSA* algorithms with these curves:

- NIST P-256
- NIST P-384
- NIST P-521

Extensions
----------

SCION relies on five X.509 extensions: Authority Key Identifier, Subject Key
Identifier, Key Usage, Extended Key Usage and Basic Constraints. Each extension
has SCION-specific constraints, summarized per certificate type in the list at
the top of this page. The `Extensions
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-15.html#name-extensions>`_
section of the SCION PKI draft specifies their definitions and constraints. Its
Tables 3 to 5 give the rules per certificate type.
