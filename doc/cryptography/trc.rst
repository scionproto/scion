********************************************
Trust Root Configuration (TRC)
********************************************

The **Trust Root Configuration (TRC)** is a signed collection of `X.509 v3
certificates
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#section-2-2>`__
and ISD policy information that establishes the trust anchors of an ISD. It contains the **CP Root Certificates** that root the verification path for
**CP AS Certificates**, together with the **Sensitive Voting Certificates** and
**Regular Voting Certificates** and the policy used to vote on the next TRC.

Like the certificates it carries, the TRC builds on [RFC5280]_/[X509]_ with more
restrictive SCION constraints. The full normative specification — payload schema,
fields, signing, updates and certification paths — is defined in the `SCION PKI
draft <https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html>`_.

.. _trc-format:

TRC Format
==========

The TRC payload is a DER-encoded container holding the ISD's policy fields and the
set of self-signed certificates that anchor trust for the ISD. Its schema, fields
and the constraints on the certificate set are specified in `TRC Fields
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-trc-fields>`_.

.. _signed-trc-format:

Signed TRC Format
=================

The TRC payload is signed as a CMS *SignedData* content and encapsulated in a CMS
*ContentInfo*, following [RFC5652]_ with SCION-specific restrictions (an empty
``certificates`` field, ``id-data`` content type, and ``IssuerAndSerialNumber``
signer identifiers). The exact CMS profile is specified in `TRC Signature Syntax
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-trc-signature-syntax>`_.

.. _trc-update:

TRC Update
==========

A TRC update is either a **regular update** (routine re-issuance with unchanged
voting quorum, core ASes, authoritative ASes and voting/root certificate sets;
votes cast by Regular Voting Certificates) or a **sensitive update** (any other
change, e.g. to policy or quorum; votes cast by Sensitive Voting Certificates).
The update rules, the regular/sensitive distinction and the verification algorithm
are specified in `TRC Updates
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-trc-updates>`_.

.. _trc-equality:

TRC Equality
============

Two TRCs are equal if and only if their payloads are byte-equal; this is sufficient
because the payload determines exactly which signatures must be attached. See `TRC
Equality
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-trc-equality>`_.

.. _trc-selection:

CP Certification Path
=====================

The certification path of a **CP AS Certificate** starts in a **CP Root
Certificate**. To validate a path, the relying party builds the trust anchor pool
of **CP Root Certificates** from the applicable TRCs (selected by verification
time, accounting for validity and grace periods) and verifies candidate paths
against it. The selection algorithm and the construction of the trust anchor pool
are specified in `Certification Path — Trust Anchor Pool
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-certification-path-trust-an>`_.

Voting Certificate
==================

There are two types of voting certificates, which authenticate the keys allowed to
cast votes in the TRC update process. Both are self-signed end-entity certificates
that follow the **CP Certificate** format, except that they need not include the
*ISD-AS number* in their distinguished name. Their full profiles are specified in
`Voting Certificates
<https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#name-voting-certificates>`_.

.. _sensitive-voting-certificate:

Sensitive Voting Certificate
----------------------------

**Sensitive Voting Certificates** authenticate the keys allowed to cast votes in a
sensitive update.

The recommended maximum validity period of a **Sensitive Voting Certificate** is
`5 years <https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#section-2.5-1>`__.

.. _regular-voting-certificate:

Regular Voting Certificate
--------------------------

**Regular Voting Certificates** authenticate the keys allowed to cast votes in a
regular update.

The recommended maximum validity period of a **Regular Voting Certificate** is
`5 years <https://www.ietf.org/archive/id/draft-dekater-scion-pki-13.html#section-2.5-1>`__.

.. _supported-algorithms:

Supported Algorithms
====================

The signature algorithms for TRCs are the same as for certificates (see
:ref:`certificate-signature`). The CMS *SignedData* of the signed TRC follows
[RFC8419]_, Section 3.1.
