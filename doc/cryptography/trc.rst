********************************************
Trust Root Configuration (TRC) Specification
********************************************

This document contains the specification for **Trust Root Configuration (TRC)**,
**Sensitive Voting Certificate** and **Regular Voting Certificate**.

For voting certificates, the *SCION Trust Root Configuration Specification*
builds on top of [RFC5280]_, which in turn builds on top of [X509]_. The SCION
specification is a more restrictive set of [RFC5280]_, which means that
[RFC5280]_ compliant implementations can be adapted to implement this
specification by including the additional checks.

For each SCION voting certificate, this document defines the additional
constraints when compared to [RFC5280]_. When something is marked as optional,
it also includes how the Anapaya implementation behaves.

Note that this document uses the new X.509-style SCION terminology (as opposed
to the previous JSON SCION terminology). The following entities are used in this
document:

- **Sensitive Voting Key**. This is the previous **offline voting key**. It is
  embedded in TRCs (via a sensitive voting certificate) to signal that a party
  can cast a vote on a sensitive update.
- **Regular Voting Key**. This is the previous **online voting key**. It is
  embedded in TRCs (via a regular voting certificate) to signal that a party can
  cast a vote on a regular update.
- **Sensitive Voting Certificate**. This is the container for the public key
  associated with the **Sensitive Voting Key**.
- **Regular Voting Certificate**. This is the container for the public key
  associated with the **Regular Voting Key**.

This document uses the Anapaya IANA Private Enterprise Number (55324) as root
SCION OIDs:

.. code-block:: text

    id-ana  ::=  OBJECT IDENTIFIER {1 3 6 1 4 1 55324}

.. _trc-format:

TRC Format
==========

The SCION TRC is a signed collection of X.509 v3 certificates and some ISD
policy information. This collection contains a set of *CP Root Certificates*
that build the roots of the verification path for *CP AS Certificates* of an
ISD. The remaining certificates are solely used, together with the ISD policy
information, for voting the next TRC in the *TRC Update Process*.

This section presents the TRC format definitions and encoding and uses the ITU-T
[X680]_ syntax.

TRC Payload Schema
------------------

The TRC payload is the container that holds the certificates and the policy
information. For signature calculation, the data that is to be signed is encoded
using ASN.1 distinguished encoding rules (DER) [X690]_.

.. code-block:: text

    TRCPayload  ::=  SEQUENCE {
        version   TRCFormatVersion,
        iD        TRCID,
        validity  Validity,

        gracePeriod   INTEGER,
        noTrustReset  BOOLEAN DEFAULT FALSE,
        votes         SEQUENCE OF INTEGER (SIZE (1..255)),

        votingQuorum  INTEGER (1..255),

        coreASes           SEQUENCE OF ASN,
        authoritativeASes  SEQUENCE OF ASN,
        description        UTF8String (SIZE (0..1024)),

        certificates       SEQUENCE OF Certificate }

    TRCFormatVersion  ::=  INTEGER { v1(0) }

    TRCID  ::=  SEQUENCE {
        iSD           ISD,
        serialNumber  INTEGER (1..MAX),
        baseNumber    INTEGER (1..MAX) }

    ISD  ::=  INTEGER (1..65535)

    Validity  ::=  SEQUENCE {
        notBefore  Time,
        notAfter   Time }

    ASN  ::=  INTEGER (1..281474976710655)


TRC Payload Fields
------------------

The sequence TRCPayload contains the identifying information of a TRC.
Furthermore, it contains policy information for TRC updates, and a list of
certificates that build the trust anchor for the ISD. The remainder of this
section describes the syntax and semantics of these fields.

.. _trc-version-field:

Version
^^^^^^^

This field describes the version of the encoded TRC payload. For now, this
version is always ``v1``.

**Deprecation warning**: note that the ``version`` field has different semantics
compared to the old SCION JSON format for TRCs (where version was an
incrementing counter). The JSON style ``version`` is moved to the ``serial number``
field in the :ref:`trc-id-field` sequence bellow.

.. _trc-id-field:

ID
^^

This field is a unique identifier of the TRC. It is a sequence of the ISD
number, TRC serial number and the base number. The ISD number MUST be in the ISD
numbering range and not be the wildcard ISD. I.e., the ISD number is an integer
in the inclusive range between 1 and 65535. The serial and base number both
MUST be a positive integer.

The base number indicates the starting point of the TRC update chain this TRC
is in. A TRC where the serial number is equal to the base number is called a
*base* TRC. Trust for a *base* TRC cannot be inferred by verifying a TRC
update, and has to be bootstrapped through another mechanism.

The *initial* TRC is a special case of a *base* TRC. It MUST hold the serial
number value 1 and base number 1. With every TRC update, the serial number MUST
be incremented by one. This facilitates uniquely identifying the predecessor and
successor TRC in a TRC update chain starting in the same base TRC.

If a trust reset is necessary, a new *base* TRC is announced to start a new and
clean TRC update chain. The base number SHOULD be the subsequent number of the
serial number of the latest TRC that was produced by a non-compromised TRC
update for this ISD.

.. _trc-validity-field:

Validity
^^^^^^^^

The TRC validity period is the interval during which the TRC may be considered
in the valid state. This interval sets the lower and upper bound for which a TRC
can be *active*.

The validity is a sequence of two dates, as defined in [X509]_, Section 7.2.

In addition to the definition, the following constraints apply:

- All TRCs MUST have a well-defined expiration date. TRCS that specify that they
  do not have a well-defined expiration date (by using the 99991231235959Z
  Generalized Time value) are not valid. SCION implementations MUST NOT create
  such TRCs, and verifiers MUST error out when encountering such a
  TRCs.

.. _trc-grace-period-field:

GracePeriod
^^^^^^^^^^^

The grace period indicates the interval for how long the previous unexpired
version of the TRC should be considered active. The field encodes the grace
period as an integer of seconds. The start of the grace period is equal to the
beginning of the validity period of this TRC.

The predecessor of this TRC, if any, should be considered active until either 1.
the grace period has passed, 2. the predecessor's expiration time is reached, or
3. the successor TRC of this TRC has been announced.

The grace period of a base TRC MUST be zero. The grace period of a non-base TRC
SHOULD be non-zero and long enough to provide sufficient overlap between the
TRCs in order to facilitate interruption free operations in the ISD. E.g., if
the grace period is too short, some CP AS certificates might expire, before the
subject can fetch an updated version from its CA.

.. _trc-no-trust-reset-field:

NoTrustReset
^^^^^^^^^^^^

This boolean indicates whether the TRC trust reset mechanism is disallowed by
the ISD. Inside a TRC update chain, this value MUST NOT change. Thus, the base
TRC decides on the value. This field is optional and defaults to FALSE.

On trust resets, this value MAY be changed. Notice, however, that this implies
that once the trust resets are disallowed, there is **no way** of re-enabling
them. ISDs SHOULD always set this value to **FALSE**, unless they have a very
specific use case and have assessed the risks and implications sufficiently.

.. _trc-votes-field:

Votes
^^^^^

Votes contains a sequence of indices of the voting certificates in the
predecessor TRC. In a *base* TRC, this sequence is empty. Every entry in this
sequence MUST be unique.

If index ``i`` is part of ``votes``, then the voting certificate at position
``i`` in the ``certificates`` sequence of the predecessor TRC casts a vote, for
this TRC. Further restrictions on the votes is discussed in :ref:`trc-update`.

This sequence is included to prevent stripping voting signatures from the TRC.
If this sequence were not included, a TRC that has more voting signatures than
the ``votingQuorum`` could be transformed into multiple verifiable TRCs with the
same payload, but different voting signature sets. This would violate the
uniqueness of a TRC, without the consent from a voting quorum.

.. _trc-voting-quorum-field:

VotingQuorum
^^^^^^^^^^^^

The voting quorum indicates the number of necessary votes on a successor TRC,
for it to be verifiable.

.. _trc-core-ases-field:

CoreASes
^^^^^^^^

CoreASes contains a sequence of AS numbers that are the core ASes in this ISD.
To revoke or add the core status for a given AS, a TRC update is necessary. The
entries in this sequence MUST be unique.

.. _trc-authoritative-ases-field:

AuthoritativeASes
^^^^^^^^^^^^^^^^^

AuthoritativeASes contains a sequence of AS numbers that are authoritative in
this ISD. To revoke or add the authoritative status for a given AS, a TRC update
is necessary. The entries in this sequence MUST be unique. Every authoritative
AS MUST be a core AS and listed there.

.. _trc-description-field:

Description
^^^^^^^^^^^

The description contains a UTF-8 encoded string that describes the ISD. This
value SHOULD NOT be empty, and MAY contain information in multiple languages.

.. _trc-certificates-field:

Certificates
^^^^^^^^^^^^

Certificates is a sequence of self-signed X.509 certificates that fall under
three categories:

- :ref:`sensitive-voting-certificate`
- :ref:`regular-voting-certificate`
- :ref:`cp-root-certificate`

The constraints on these certificates are described in their respective
sub-sections.

Certificates that do not fall under one of these categories MUST NOT be included
in the certificates sequence. There are some additional constraints on the set
of certificates. For each certificate, the following constraints MUST hold:

#. Every certificate MUST be unique in the sequence.
#. The Issuer/SerialNumber-pair for every certificate MUST be unique.
#. If an ISD-AS number is present in the distinguished name, the ISD field MUST
   be equal to the ISD number of this TRC defined in :ref:`trc-id-field`.
#. Every certificate MUST have a validity period that fully contains the
   validity period of this TRC. I.e., the TRC's ``not_before`` MUST be greater
   or equal to the certificate's ``not_before``, and the TRC's ``not_after``
   MUST be less or equal to the certificate's ``not_after``.
#. Per certificate category, every certificate distinguished name MUST be
   unique.

For the the set of certificates, the following MUST hold:

#. :ref:`trc-voting-quorum-field` <= count(Sensitive Voting Certificates)
#. :ref:`trc-voting-quorum-field` <= count(Regular Voting Certificate)

.. _signed-trc-format:

Signed TRC Format
-----------------

The TRC payload is signed as a *CM Signed-data Content* defined in [RFC5652]_,
Section 5, and encapsulated in a *CMS ContentInfo* defined in [RFC5652]_,
Section 3.

For convenience, the definitions are repeated here:

.. code-block:: text

    ContentInfo ::= SEQUENCE {
        contentType ContentType,
        content [0] EXPLICIT ANY DEFINED BY contentType }

    ContentType ::= OBJECT IDENTIFIER

    SignedData  ::=  SEQUENCE {
        version               CMSVersion,
        digestAlgorithms      DigestAlgorithmIdentifiers,
        encapContentInfo      EncapsulatedContentInfo,
        certificates      [0] IMPLICIT CertificateSet OPTIONAL,
        crls              [1] IMPLICIT RevocationInfoChoices OPTIONAL,
        signerInfos           SignerInfos }

    DigestAlgorithmIdentifiers  ::=  SET OF DigestAlgorithmIdentifier

    SignerInfos  ::=  SET OF SignerInfo

    EncapsulatedContentInfo  ::=  SEQUENCE {
        eContentType      ContentType,
        eContent      [0] EXPLICIT OCTET STRING OPTIONAL }

    SignerInfo  ::=  SEQUENCE {
        version                 CMSVersion,
        sid                     SignerIdentifier,
        digestAlgorithm         DigestAlgorithmIdentifier,
        signedAttrs         [0] IMPLICIT SignedAttributes OPTIONAL,
        signatureAlgorithm      SignatureAlgorithmIdentifier,
        signature               SignatureValue,
        unsignedAttrs       [1] IMPLICIT UnsignedAttributes OPTIONAL }

    SignerIdentifier  ::=  CHOICE {
        issuerAndSerialNumber      IssuerAndSerialNumber,
        subjectKeyIdentifier   [0] SubjectKeyIdentifier }

    SignedAttributes  ::=  SET SIZE (1..MAX) OF Attribute

    UnsignedAttributes  ::=  SET SIZE (1..MAX) OF Attribute

    Attribute  ::=  SEQUENCE {
        attrType    OBJECT IDENTIFIER,
        attrValues  SET OF AttributeValue }

    AttributeValue  ::=  ANY

    SignatureValue  ::=  OCTET STRING

We build on top of the rules from [RFC5652]_ and add the following restrictions:

- The ``certificates`` field in ``SignedData`` is left empty. The certificate
  pool used to verify the TRC updates is based on the previous TRC.
- The ``eContentType`` is set to ``id-data``. The contents of the ``eContent``
  is the DER encoded ``TRCPayload``, as specified above. This has the benefit that
  the format is backwards compatible with PKCS #7, as described in [RFC5652]_,
  Section 5.2.1.
- Because we do not include certificates in ``SignedData`` and choose
  ``id-data`` as the content type, the ``version`` in ``SignedData`` MUST be 1,
  as required by [RFC5652]_, Section 5.1.
- The ``SignerIdentifier`` MUST be the choice ``IssuerAndSerialNumber``, thus,
  ``version`` in ``SignerInfo`` MUST be 1, as required by [RFC5652]_, Section 5.3.
- The ``digestAlgorithm`` is implied by the ``signatureAlgorithm`` according to
  the :ref:`supported-algorithms`.
- The ``signatureAlgorithm`` MUST one of the listed :ref:`supported-algorithms`.

Anapaya software does not implement support for adding custom signed or unsigned
attributes.

.. _trc-update:

TRC Update
==========

TRC updates are split into two categories: Sensitive and regular updates. The
type of update is inferred from the information that is changed by the updated
TRC. Based on the category of the update, a different set of voters is
necessary to create a verifiable TRC update.

The following rules MUST hold for both update categories:

- The ``isd`` and ``baseNumber`` in the :ref:`trc-id-field` field MUST NOT
  change. - The ``serialNumber`` in the ``iD`` field MUST be incremented by one.
- The ``noTrustReset`` field MUST NOT change.
- There MUST only be votes cast that are authenticated by **Sensitive Voting
  Certificates** or **Regular Voting Certificates** present in the predecessor
  TRC. This means, the ``votes`` sequence MUST only contain indices of the
  **Sensitive Voting Certificates** or **Regular Voting Certificates**.
- The number of votes MUST be greater than or equal to the ``votingQuorum`` of
  the predecessor TRC.
- Every **Sensitive Voting Certificate** and **Regular Voting Certificate**
  that is new in the TRC attaches a signature to the TRC. This is done to ensure
  the freshly included voting entity agrees with the contents of the TRC and
  being part of it.

In the context of a TRC update, we identify a certificate as *changing*, if the
certificate is part of the ``certificates`` sequence in the predecessor TRC, but
no longer part of the ``certificates`` sequence in the successor TRC, and
instead, there is a certificate of the same category and distinguished name in
the ``certificates`` of the successor TRC.

We identify a certificate as *new*, if there is no certificate of the same
category and distinguished name in the ``certificates`` of the predecessor TRC.

.. _regular-trc-update:

Regular TRC Update
------------------

A TRC update qualifies as a regular update, if all of the following restrictions
apply:

- The ``votingQuorum`` does not change.
- The ``coreASes`` section does not change.
- The ``authoritativeASes`` section does not change.
- The number of **Sensitive Voting Certificates**, **Regular Voting
  Certificates**, and **CP Root certificates** and their distinguished names
  does not change.
- The set of **Sensitive Voting Certificates** does not change.
- For every **Regular Voting Certificate** that changes, the **Regular Voting
  Certificate** in the predecessor TRC is part of the voters on the successor
  TRC.
- For every **CP Root Certificate** that changes, the **CP Root Certificate** in
  the predecessor TRC attaches a signature to the signed successor TRC.

In order for a regular TRC update to be verifiable, all votes MUST be cast by a
*Regular Voting Certificate*.

.. _sensitive-trc-update:

Sensitive TRC Update
---------------------

If a TRC update does not qualify as a regular update, it is considered a
sensitive update. In order for sensitive updates to be verifiable, all votes
MUST be cast by a **Sensitive Voting Certificate**.

.. _trc-update-verification:

TRC Update Verification
-----------------------

To verify a TRC update, the relying party first checks that the specified
:ref:`trc-update` are respected. Then, the relying party checks whether the
update is regular or sensitive. In case of a regular update, the relying party
checks that signatures for the changing certificates are present and verifiable.
Further, the relying party checks that all votes are cast by a **Regular Voting
Certificate**. In case of a sensitive update, the relying party checks that all
votes are cast by a **Sensitive Voting Certificate**. In both cases, the relying
party checks that all signatures are verifiable, and no superfluous signatures
are attached.

.. _trc-equality:

TRC Equality
============

For certain operations, we require an equality definition for TRCs. The signer
infos in the signed TRC are part of an unordered set, per [RFC5652]_. This
implies, that the signer infos can be reordered without affecting verification.

**Two TRCs are equal, if and only if their payloads are byte equal.**

This definition of equality is sufficient, because the payload defines exactly
which signatures need to be attached in the signed TRC. The required signature
for voting certificates are explicitly mentioned in the ``votes`` field of the
payload. The required signatures for *new* certificates is implied by the TRC
payload, and, in case of a TRC update, the predecessor payload.

CP Certification Path
=====================

The certification path of a **CP AS Certificate** starts in a **CP Root
Certificate**. The **CP Root Certificates** for a given ISD are distributed via
the TRC. When validating the certification path, the relying party must build
the correct set of **CP Root Certificates** as a trust anchor pool from the
available TRCs. Based on this pool, the relying party can select candidate
certification paths and verify them.

.. _trc-selection:

TRC Selection
-------------

To build the trust anchor pool, the right set of TRCs must be selected. This
depends on the time of verification. In the usual case, we want to verify a
control plane message, and thus, the time will be the current time. In some
special cases, i.e., for auditing, we might want to know if a signature was
verifiable at a given point in time.

The selection algorithm is described in pseudo-python code below:

.. code-block:: python

    def select_trust_anchors(trcs: Dict[(int,int), TRC], verification_time: int) -> Set[RootCert]:
        """
        Args:
            trcs: The dictionary mapping (serial number, base number) to the TRC for a given ISD.
            verification_time: The time of verification.

        Returns:
            The set of CP Root certificates that act as trust anchors.
        """
        # Find highest base number that has a TRC with a validity period
        # starting before verification time.
        base_nr = 1
        for trc in trcs.values():
            if trc.id.base_nr > base_nr and trc.validity.not_before <= verification_time:
                base_nr = trc.id.base_nr

        # Find TRC with highest serial number with the given base number and a
        # validity period starting before verification time.
        serial_nr = 1
        for trc in trcs[isd].values():
            if trc.id.base_nr != base_nr:
                continue
            if trc.id.serial_nr > serial_nr and trc.validity.not_before <= verification_time:
                serial_nr = trc.id.serial_nr

        candidate = trcs[(serial_nr, base_nr)]

        # If the verification time is not inside the validity period,
        # there is no valid set of trust anchors.
        if not candidate.validity.contains(verification_time):
            return set()

        # If the grace period has passed, only the certificates in that TRCs
        # may be used as trust anchors.
        if candidate.validity.not_before + candidate.grace_period < verification_time:
            return collect_trust_anchors(candidate)

        predecessor = trcs.get((serial_nr-1, base_nr))
        if not predecessor or predecessor.validity.not_after < verification_time:
            return collect_trust_anchors(candidate)

        return collect_trust_anchors(candidate) | collect_trust_anchors(predecessor)


    def collect_trust_anchors(trc: TRC) -> Set[RootCert]:
        """
        Args:
            trc: A TRC from which the CP Root Certificates shall be extracted.

        Returns:
            The set of CP Root certificates that act as trust anchors.
        """
        roots = set()
        for cert in trc.certificates:
            if not cert.basic_constraints.ca:
                continue
            roots.add(cert)
        return roots

Voting Certificate
==================

There are two types of voting certificates; The **Sensitive Voting Certificate**
and the **Regular Voting Certificates**. They authenticate public keys for
private keys that are allowed to cast votes in the TRC update process.

Both certificates are x.509 style certificates, in general follow the **CP
Certificates** format, with the exception that they are not required to include
the ``ISD-AS number`` in their distinguished name.

.. _sensitive-voting-certificate:

Sensitive Voting Certificate
----------------------------

**Sensitive Voting Certificates** state which keys are allowed to cast votes in
a sensitive update.

In X.509 terms, **Sensitive Voting Certificates** are *self-signed* end-entity
certificates (``issuer`` and ``subject`` are the same entity, and the key within
the certificate was used to sign it).

All constraints in :ref:`general-certificate-requirements` apply to **Sensitive
Voting Certificates**.

The recommended maximum validity period of a **Sensitive Voting Certificate** is
5 year.

Extension constraints
^^^^^^^^^^^^^^^^^^^^^

**Key usage**. If this extension is present, the ``digitalSignature`` and
``keyCertSign`` attribute MUST NOT be set.

**Extended key usage**. This extension MUST be present. The ``id-kp-serverAuth``
and ``id-kp-clientAuth`` purposes MUST NOT be set. The ``id-kp-sensitive``
and ``id-kp-timeStamping`` purpose MUST be set.

.. code-block:: text

    id-kp-sensitive AttributeType ::= {id-ana id-cppki(1) id-kp(3) 1}

**Basic constraints**. The extension SHOULD NOT be included. If it is included,
the ``cA`` component MUST be set to **FALSE**.

.. _regular-voting-certificate:

Regular Voting Certificate
--------------------------

**Regular Voting Certificates** state which keys are allowed to cast votes in a
regular update.

In X.509 terms, **Regular Voting Certificates** are *self-signed* end-entity
certificates (``issuer`` and ``subject`` are the same entity, and the key within
the certificate was used to sign it).

All constraints in :ref:`general-certificate-requirements` apply to **Regular
Voting Certificates**.

The recommended maximum validity period of a **Regular Voting Certificate** is 1
year.

Extension constraints
^^^^^^^^^^^^^^^^^^^^^

**Key usage**. If this extension is present, the ``digitalSignature`` and
``keyCertSign`` attribute MUST NOT be set.

**Extended key usage**. This extension MUST be present. The ``id-kp-serverAuth``
and ``id-kp-clientAuth`` purposes MUST NOT be set. The ``id-kp-regulars``
and ``id-kp-timeStamping`` purpose MUST be set.

.. code-block:: text

    id-kp-regular AttributeType ::= {id-ana id-cppki(1) id-kp(3) 2}

**Basic constraints**. The extension SHOULD NOT be included. If it is included,
the ``cA`` component MUST be set to **FALSE**.

.. _supported-algorithms:

Supported Algorithms
====================

See :ref:`certificate-signature` for information about supported algorithms.
In this section we only list the TRC-specific aspects.

The Signed-data of the signed TRC format follows [RFC8419]_, Section 3.1.
