*************************
Certificates
*************************

.. highlight:: text

SCION uses three types of X.509 v3 **Control Plane (CP) certificates** that build
on top of [RFC5280]_ (which in turn builds on [X509]_), adding more restrictive
SCION-specific constraints:

- :ref:`CP Root Certificate <cp-root-certificate>`
- :ref:`CP CA Certificate <cp-ca-certificate>`
- :ref:`CP AS Certificate <cp-as-certificate>`

Additionally, SCION uses two **voting certificates** - the *sensitive voting
certificate* and the *regular voting certificate* - which carry the keys that
cast votes in the TRC update process (see the :doc:`TRC Specification <trc>`).

The full normative specification — certificate fields, per-type profiles,
extensions and the ASN.1 syntax — is defined in the `SCION PKI draft
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html>`_.

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
``extensions`` fields — including which [RFC5280]_/[X509]_ options are forbidden
or constrained in SCION — are given in `X.509 Certificate Profiles and Constraints
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-x509-certificate-profiles-a>`_.

.. _certificate-signature:

Signature
---------

For security reasons, SCION uses a custom list of acceptable algorithms.
The accepted algorithms and curves and the ``AlgorithmIdentifier``
ASN.1 are listed in the `Signature field
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-signature>`_
section and `Appendix A
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-certificate-extensions-in-a>`_
of the SCION PKI draft.

This implementation supports all three mandatory algorithms - *ECDSA* with the curves:

- NIST P-256
- NIST P-384
- NIST P-521

Extensions
----------

SCION relies on five X.509 extensions — Authority Key Identifier, Subject Key
Identifier, Key Usage, Extended Key Usage and Basic Constraints — each with
SCION-specific constraints (the per-type specifics are summarized per certificate
type below). Their definitions and constraints are specified in the `Extensions
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-extensions>`_
section of the SCION PKI draft.

.. _cp-root-certificate:

CP Root Certificate
===================

**CP Root Certificates** state which ASes are CA ASes for an ISD. They are
self-signed CA certificates owned by CA ASes, and are embedded in TRCs to
bootstrap trust (see the :doc:`TRC Specification <trc>`). Their full profile —
key usage, extended key usage (including ``id-kp-root``) and basic constraints
(``cA`` TRUE, ``pathLenConstraint`` 1) — is specified in `Control Plane Root
Certificate
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-control-plane-root-certific>`_.

.. _cp-ca-certificate:

CP CA Certificate
=================

**CP CA Certificates** are used by CA ASes to sign **CP AS Certificates**. They
are self-issued CA certificates, signed by a **CP Root Certificate**. Their full
profile — key usage, extended key usage and basic constraints (``cA`` TRUE,
``pathLenConstraint`` 0) — is specified in `Control Plane Issuing CA Certificate
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-control-plane-issuing-ca-ce>`_.

.. _cp-as-certificate:

CP AS Certificate
=================

**CP AS Certificates** are the end-entity certificates SCION ASes use to sign
control plane messages. Their full profile — key usage (``digitalSignature``),
extended key usage (``id-kp-timeStamping``, and ``id-kp-serverAuth`` /
``id-kp-clientAuth`` for CP TLS sessions) and basic constraints — is specified in
`Control Plane AS Certificate
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-control-plane-as-certificat>`_.
