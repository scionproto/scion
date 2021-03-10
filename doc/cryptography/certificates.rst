*************************
Certificate Specification
*************************

.. highlight:: text

This document contains the specification for **Control Plane (CP) Root
Certificates**, **CP CA Certificates** and **CP AS Certificates**.

The *SCION Certificate Specification* builds on top of [RFC5280]_, which in turn
builds on top of [X509]_. The SCION specification is a more restrictive set of
[RFC5280]_, which means that [RFC5280]_ compliant implementations can be adapted
to implement this specification by including the additional checks.

For each SCION CP certificate, this document defines the additional constraints
when compared to [RFC5280]_. When something is marked as optional, it also
includes how the Anapaya implementation behaves.

Note that this document uses the new X.509-style SCION terminology (as opposed
to the previous JSON SCION terminology). The following entities are used in this
document:

- **CP Root Key**. This is the previous **Issuing key**/**Issuing grant key**.
  It is embedded in TRCs (via a certificate) to signal that an AS can act as a
  certificate authority in the ISD (a CA AS).
- **CP Root Certificate**. This is the container for the public key associated
  with the **CP Root Key**.
- **CP CA Key**. This is the previous **Issuing key**. It is used by CA ASes to
  sign AS certificates.
- **CP CA Certificate**. This is the container for the public key associated
  with the **CP AS Key**.
- **CP AS Key**. This is the previous **Signing key**. It is used by an AS to
  sign control-plane messages.
- **CP AS Certificate**. This is the container for the public key associated
  with the **CP AS Key**.

This documents assumes a trusted set of **CP Root Certificates** already exists.
How such a set is selected is outside the scope of this document, and described
in the *TRC Specification*.

This document uses the Anapaya IANA Private Enterprise Number (55324) as root
SCION OIDs:

.. code-block:: text

    id-ana ::= OBJECT IDENTIFIER {1 3 6 1 4 1 55324}

.. _general-certificate-requirements:

General certificate requirements
================================

SCION CP certificates are X.509 v3 certificates. Every certificate has a
**subject** (the entity that owns the certificate) and a **issuer** (the entity
that issued the certificate, usually a CA). Like in Internet PKI, in SCION
sometimes both the **subject** and the **issuer** can be the same entity.

The listing below shows the generic format of SCION CP certificates. For
information regarding the full format, please see [X509]_, clause 7.2.

.. code-block:: text

    TBSCertificate ::= SEQUENCE {
        version               [0]   EXPLICIT Version DEFAULT v1,
        serialNumber                CertificateSerialNumber,
        signature                   AlgorithmIdentifier{{SupportedAlgorithms}},
        issuer                      Name,
        validity                    Validity,
        subject                     Name,
        subjectPublicKeyInfo        SubjectPublicKeyInfo,
        issuerUniqueID        [1]   IMPLICIT UniqueIdentifier OPTIONAL, -- disallowed in SCION
        subjectUniqueID       [2]   IMPLICIT UniqueIdentifier OPTIONAL, -- disallowed in SCION
        extensions            [3]   EXPLICIT Extensions OPTIONAL
    }

    Version ::= INTEGER { v1(0), v2(1), v3(2)}  -- v1, v2 disallowed in SCION
    CertificateSerialNumber ::= INTEGER

    Validity ::= SEQUENCE {
        notBefore Time,
        notAfter Time
    }

    Time ::= CHOICE {
        utcTime UTCTime,
        generalizedTime GeneralizedTime
    }

    SubjectPublicKeyInfo ::= SEQUENCE {
        algorithm         AlgorithmIdentifier{{SupportedAlgorithms}},
        subjectPublicKey  BIT STRING
    }

    Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension

    Extension ::= SEQUENCE {
        extnId      OBJECT IDENTIFIER,
        critical    BOOLEAN DEFAULT FALSE,
        extnValue   OCTET STRING
                        -- contains DER encoding of ASN.1 value
                        -- corresponding to type identified by extnID
    }

Version
-------

The ``version`` field is always ``v3`` in SCION; this is required because
`extensions` are mandatory.

**Deprecation warning**: note that the X.509 ``version`` field has different
semantics compared to the old SCION JSON format for certificates (where version
was an incrementing counter).

Serial number
-------------

The ``serialNumber`` is used like in [RFC5280]_.

.. _certificate-signature:

Signature
---------

For security reasons, SCION uses a custom list of acceptable algorithms. The
list currently contains only the *ECDSA* signature algorithm (defined in
[X962]_).

The OIDs for *ECDSA* are defined as ``ecdsa-with-SHA256``,
``ecdsa-with-SHA384``, and ``ecdsa-with-SHA512`` in [RFC5758]_. We include them
here::

    sigAlg-ecdsa-SHA256      ALGORITHM         ::= { OID ecdsa-with-SHA256 }
    sigAlg-ecdsa-SHA384      ALGORITHM         ::= { OID ecdsa-with-SHA384 }
    sigAlg-ecdsa-SHA512      ALGORITHM         ::= { OID ecdsa-with-SHA512 }

    ecdsa-with-SHA256 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
        us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 2 }
    ecdsa-with-SHA384 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
        us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 3 }
    ecdsa-with-SHA512 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
        us(840) ansi-X9-62(10045) signatures(4) ecdsa-with-SHA2(3) 4 }

The only accepted curves for *ECDSA* are:

- NIST P-256 ([NISTFIPS186-4]_, section D.1.2.3) (named ``secp256r1`` in [RFC5480]_)
- NIST P-384 ([NISTFIPS186-4]_, section D.1.2.4) (named ``secp384r1`` in [RFC5480]_)
- NIST P-521 ([NISTFIPS186-4]_, section D.1.2.5) (named ``secp521r1`` in [RFC5480]_)

The OIDs for the above curves are::

    secp256r1 OBJECT IDENTIFIER ::= {
       iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
       prime(1) 7 }
    secp384r1 OBJECT IDENTIFIER ::= {
       iso(1) identified-organization(3) certicom(132) curve(0) 34 }
    secp521r1 OBJECT IDENTIFIER ::= {
       iso(1) identified-organization(3) certicom(132) curve(0) 35 }

If an ECDSA key is used to produce a signature, the appropriate hash size should
be used:

- If the signing key is P-256, the signature should use ECDSA with with SHA-256
- If the signing key is P-384, the signature should use ECDSA with with SHA-384
- If the signing key is P-521, the signature should use ECDSA with with SHA-512


Implementations MUST include support for P-256, P-384, and P-521.

Note that the list might be extended in the future. SCION implementations must
reject cryptographic algorithms not found on the list. This document currently
serves as the list of accepted cryptographic algorithms.

For convenience, the ``AlgorithmIdentifier`` definition is included below:

.. code-block:: text

   AlgorithmIdentifier  ::=  SEQUENCE  {
       algorithm   OBJECT IDENTIFIER,
       parameters  ANY DEFINED BY algorithm OPTIONAL
   }

As defined in [RFC8410]_, the ``parameters`` field must be absent. If the
``AlgorithmIdentifier`` is not the above, SCION implementations must error out.

.. _issuer:

Issuer
------

``issuer`` contains the distinguished name (DN) of the CA that created the
certificate. The ``issuer`` field must be non-empty.

The syntax for ``Name`` is defined in [X501]_ (10/2016), clause 9.2. For
reference, it is:

.. code-block:: text

    Name ::= CHOICE {
        rdnSequence RDNSequence
    }

    RDNSequence ::= SEQUENCE OF RelativeDistinguishedName

    RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue

    AttributeType ::= OBJECT IDENTIFIER

    AttributeValue ::= ANY -- DEFINED BY AttributeType

Generally, the type will be a ``DirectoryString`` type, outlined below:

.. code-block:: text

    DirectoryString ::= CHOICE {
        teletexStrings TeletexString (SIZE (1..MAX)),
        printableString PrintableString (SIZE (1..MAX)),
        universalString UniversalString (SIZE (1..MAX)),
        utf8String UTF8String (SIZE (1..MAX)),
        bmpString BMPString (SIZE (1..MAX)),
    }

SCION implementation must support the following standard attribute types:

- country
- organization
- organizational unit
- distinguished name qualifier
- state or province name
- common name
- serial number
- ISD-AS number

Other than ``ISD-AS number``, all the above attributes are defined in [RFC5280]_
as an added restriction when compared to the RFC, SCION implementations must use
the ``UTF8String`` value type.

The *ISD-AS number* attribute is used to identify the SCION ISD and AS. The
attribute type is ``id-at-ia``, defined as:

.. code-block:: text

    id-at-ia AttributeType ::= {id-ana id-cppki(1) id-at(2) 1}

The attribute value for the *ISD-AS number* type is a ``UTF8String`` following
the formatting defined in `ISD and AS numbering
<https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering>`_. For example,
AS ``ff00:0:110`` in ISD ``1`` is formatted as ``1-ff00:0:110``.

The *ISD-AS number* must be present exactly once in all SCION CP certificates.
Implementations must not create nor successfully verify certificates that do not
include the *ISD-AS number*, or include it more than once.

SCION implementations may support other attributes.

Validity
--------

The ``validity`` field is defined as in [RFC5280]_, Section 4.1.2.5.

In addition to the definition, the following constraints apply to SCION CP
certificates:

- All certificates must have a well-defined expiration date. SCION CP certificates
  that specify that they do not have a well-defined expiration date (by using
  the 99991231235959Z Generalized Time value) are not valid. SCION
  implementations must not create such certificates, and verifiers must error
  out when encountering such a certificate.
- The validity period of a certificate (defined as the duration between
  ``notBefore`` and ``notAfter``) must be under a specific value. The exact value is
  listed in the sections detailing each certificate type.

Subject
-------

The ``subject`` field describes the entity that owns the certificate. It is
defined in the same way as the ``issuer`` field (see :ref:`issuer`). All SCION
CP certificates MUST have the ``subject`` field defined (with the same
requirements as the ``issuer`` field).

Subject public key info
-----------------------

Field ``subjectPublicKeyInfo`` is used to carry the public key of the subject
and identify which algorithm should be used with the key. The SCION constraints
in section :ref:`certificate-signature` still apply: the key must be a valid key
for the selected curve, and the algorithm must be ``sigAlg-ecdsa``.

Extensions
----------

This section includes only extensions that SCION relies on. For each extension,
the way the Anapaya implementation deals with the extension is also listed.

Anapaya software does not implement extensions other than those listed in this
document.

Authority key identifier extension
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This extension is defined [X509]_, clause 9.2.2.1.

The authority key identifier extension is used to determine which public key was
used to sign the certificate.

.. code-block:: text

    authorityKeyIdentifier EXTENSION ::= {
        SYNTAX AuthorityKeyIdentifier
        IDENTIFIED BY id-ce-authorityKeyIdentifier
    }

    AuthorityKeyIdentifier ::= SEQUENCE {
        keyIdentifier             [0]   KeyIdentifier OPTIONAL,
        authorityCertIssuer       [1]   GeneralNames OPTIONAL,
        authorityCertSerialNumber [2]   CertificateSerialNumber OPTIONAL,
        ...
    }
    (WITH COMPONENTS {..., authorityCertIssuer PRESENT,
                            authorityCertSerialNumber PRESENT } |
    WITH COMPONENTS {..., authorityCertIssuer ABSENT,
                            authorityCertSerialNumber ABSENT } )

    KeyIdentifier ::= OCTET STRING

SCION implementations may implement support for ``authorityCertIssuer`` and
``authorityCertSerialNumber``, but ``keyIdentifier`` is the preferred way of
using the extension. If ``authorityCertIssuer`` or ``authorityCertSerialNumber``
are set and support for them is missing, implementations should error out.

**Anapaya implementation**. The current Anapaya implementation supports this
extension (required by [RFC5280]_).

This extension must always be non-critical. However, SCION implementations must
error out if it is not present and the certificate is not self-signed.

.. _subject-key-identifier-extension:

Subject key identifier extension
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This extension is defined in [X509]_ (10/2016), clause 9.2.2.2.

The subject key identifier extension identifies the public key being certified.
It allows for overlapping CP CA keys, for example during updates.

.. code-block:: text

    subjectKeyIdentifier EXTENSION ::= {
        SYNTAX SubjectKeyIdentifier
        IDENTIFIED BY id-ce-subjectKeyIdentifier
    }

    SubjectKeyIdentifier ::= KeyIdentifier

**Anapaya implementation**. The current Anapaya implementation supports this
extension (this can be used by control-plane messages to identify which
certificate to use for verification).

This extension must always be non-critical. However, SCION implementations must
error out if it is not present.

Key usage extension
^^^^^^^^^^^^^^^^^^^

This extension is defined in [X509]_ (10/2016), clause 9.2.2.3.

The key usage extension dictates how the public key within a certificate may be
used. The ASN.1 definition is as follows:

.. code-block:: text

    keyUsage EXTENSION ::= {
        SYNTAX KeyUsage
        IDENTIFIED BY id-ce-keyUsage
    }

    KeyUsage ::= BIT STRING {
        digitalSignature  (0),
        contentCommitment (1),
        keyEncipherment   (2),
        dataEncipherment  (3),
        keyAgreement      (4),
        keyCertSign       (5),
        cRLSign           (6),
        encipherOnly      (7),
        decipherOnly      (8),
    }

Each key usage attribute has the following semantics in SCION:

- ``digitalSignature``: the key can be used to sign control-plane payloads
- ``contentCommitment``: not used
- ``keyEncipherment``: not used
- ``dataEncipherment``: not used
- ``keyAgreement``: not used
- ``keyCertSign``: the key can be used to sign certificates
- ``cRLSign``: not used
- ``encipherOnly``: not used
- ``decipherOnly``: not used

Note that whenever a certificate is used for ``digitalSignature``, there needs to
be a way to go back from the signature to the certificate/key that signed it.
This can be easily done by referencing the ISD-AS and Subject Key Identifier.
For more information about the latter, see :ref:`subject-key-identifier-extension`.

Each control-plane certificate type has different key usage attributes. These
are listed in the certificate descriptions below.

When this extension is present, it should be marked as critical.

Extended key usage extension
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

This extension is defined in [X509]_, clause 9.2.2.4.

The extended key usage extension adds one or more purposes for which the
certified public key may be used.

It is defined as follows:

.. code-block:: text

    extKeyUsage EXTENSION ::= {
        SYNTAX             SEQUENCE SIZE (1..MAX) OF KeyPurposeId
        IDENTIFIED BY      id-ce-extKeyUsage
    }

    KeyPurposeId ::= OBJECT IDENTIFIER

This extension may be present in SCION certificates. Note that certain CP interactions
require it (see the certificate-specific sections below for details).

The following extended key usage defined by [RFC5280]_, Section 4.2.1.12, are used by
SCION:

- ``id-kp-serverAuth``: means that the key can be used for SCION CP server authentication
- ``id-kp-clientAuth``: means that the key can be used for SCION CP client authentication

Each control-plane certificate type has different extended key usage attributes. These are
listed in the certificate descriptions below.

Basic constraints extension
^^^^^^^^^^^^^^^^^^^^^^^^^^^

This extension is defined in [X509]_,  clause 9.4.2.1.

The basic constraints extension specifies whether the subject may act as a CA.

The ASN.1 definition is as follows:

.. code-block:: text

    basicConstraints EXTENSION ::= {
        SYNTAX          BasicConstraintsSyntax
        IDENTIFIED BY   id-ce-basicConstraints
    }

    BasicConstraintsSyntax ::= SEQUENCE {
        cA                BOOLEAN DEFAULT FALSE,
        pathLenConstraint INTEGER(0..MAX) OPTIONAL,
    }

Each control-plane certificate has different basic constraints. There are listed
in the certificate descriptions below.

.. _cp-root-certificate:

CP Root Certificate
===================

**CP Root Certificates** state which ASes are CA ASes for an ISD.

In X.509 terms, **CP Root Certificates** are *self-signed* CA certificates
(``issuer`` and ``subject`` are the same entity, and the key within the
certificate was used to sign it). They are owned by CA ASes.

To bootstrap trust for **CP Root Certificates**, they are embedded in TRCs (see
the TRC document for more information about the embedding). This is also how the
set of ASes that can issue certificates for an ISD is defined.

All constraints in :ref:`general-certificate-requirements` apply to **CP Root Certificates**.

The recommended maximum validity period of a **CP Root certificate** is 1 year.

Extension constraints
---------------------

**Key usage**.  The ``keyCertSign`` attributes must be set. The
``digitalSignature`` attribute must not be set, as in the context of SCION this
has the semantics of *allowed to sign control-plane messages*.

**Extended key usage**. This extension must present. The ``id-kp-serverAuth``
and ``id-kp-clientAuth`` purposes must not be set. The ``id-kp-root`` and
``id-kp-timeStamping`` purpose must be set.

.. code-block:: text

    id-kp-root AttributeType ::= {id-ana id-cppki(1) id-kp(3) 3}

**Basic constraints**. The extension must be present, with the ``cA`` component
set to **TRUE**. The ``pathLenConstraint`` value should be set to 1. Note that
X.509 requires that this be marked as critical.

.. _cp-ca-certificate:

CP CA Certificate
=================

**CP CA Certificates** are used by CA ASes for signing **CP AS Certificates**.

In X.509 terms, **CP CA Certificates** are *self-issued* CA certificates
(``issuer`` and ``subject`` are the same entity). They are owned by CA ASes.

**CP CA Certificates** are signed by **CP Root Certificates**.

The recommended maximum validity period of a **CP CA certificate** is 1 week.

Extension constraints
---------------------

**Key usage**. The ``keyCertSign`` attributes must be set. The
``digitalSignature`` attribute must not be set, as in the context of SCION this
has the semantics of *allowed to sign control-plane messages*.

**Extended key usage**. This extension may be present. If it is present, the
``id-kp-serverAuth`` and ``id-kp-clientAuth`` purposes must not be present.

**Basic constraints**. The extension must be present, with the ``cA`` component
set to **TRUE**. The ``pathLenConstraint`` value should be set to 0. This means
that the subject can only issue end-entity certificates. Note that X.509
requires that this be marked as critical.

.. _cp-as-certificate:

CP AS Certificate
=================

**CP AS Certificates** are used by SCION ASes to sign control-plane messages.

In X.509 terms, **CP AS Certificates** are end-entity certificates.

The recommended maximum validity period of a **CP AS certificate** is 3 days.

Extension constraints
---------------------

**Key usage**. The ``digitalSignature`` attribute must be set.
The ``keyCertSign`` attribute must not be set.

**Extended key usage**. This extension must be present. ``id-kp-timeStamping``
must be set. If used on the server-side of CP TLS session establishment,
``id-kp-serverAuth`` must be set. If used on the client-side of a CP TLS session
establishment, ``id-kp-clientAuth`` must be set.

**Basic constraints**. The extension should not be included.

Resources
=========

Most of the references linked from this document can be found in the `Anapaya
standards repository
<https://drive.google.com/drive/u/0/folders/1q-3mN6Q6R8Rgc_jiwW8G8ua_ABwFb4BA>`_.
