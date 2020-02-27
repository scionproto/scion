# Control-Plane PKI

The control-plane PKI (CP-PKI) allows each isolation domain (ISD) to define its own roots of trust
for ISD and AS identities. Each ISD maintains its own trust root configuration (TRC), where the
primary ASes of the ISD are specified along with public keys and policies for updating the TRC. Each
version of the TRC must be signed by a number of ASes with voting power in the ISD, so that updates
can be authenticated and validated against previous versions. The TRC can be seen as a
multi-self-signed root certificate.

This document largely borrows from previous design documents and the SCION book, but also proposes
new concepts and simplifies some existing mechanisms.

## Glossary

- __Grace period:__ number of seconds during which the previous version of a TRC is still considered
  active after a new version has been published.
- __Trust anchor:__ certificate, public key, or set thereof that is considered valid axiomatically
  (unless expired or revoked). In other words, a cryptographic object for which trust is assumed
  rather than derived. In SCION, trust anchors are TRCs with a grace period of 0.
- __Relying party:__ any entity holding at least one trust anchor and capable of verifying TRCs and
  AS certificates. All SCION hosts are relying parties. A relying party (similarly to how they are
  defined in [RFC 3647](https://tools.ietf.org/html/rfc3647)) is an entity that uses a public key in
  a TRC or certificate (e.g., for signature verification or encryption).
- __Trust store:__ database of trust anchors established and maintained by relying parties.
- __Trust reset:__ action of creating and announcing a new trust anchor for an existing ISD.
- __TRC update:__ process of releasing a new TRC version that is verifiable with the previous
  version. Starting from a trust anchoring TRC, consecutive updates build a verifiable chain of
  updates.
- __TRC chain verification:__ process of verifying a series of TRCs with consecutive version numbers
  and the same ISD identifier, starting from a trust anchor.
- __ASCII__, __BASE64URL__, __UTF8:__ defined according to [Section 1.1 of RFC
  7515](https://tools.ietf.org/html/rfc7515#section-1.1).

### TRC Qualifiers

Below are the different states in which a TRC can be (in increasing level of "trustworthiness"),
from the perspective of a relying party:

1. __Verified:__ a TRC whose format and contents are correct and consistent with previous versions.
    The verification of a TRC includes basic sanity checks, such as ensuring [TRC
    invariants](#trc-invariants) and [TRC update validation](#trc-updates), as well as a TRC chain
    verification.
1. __Valid:__ a *verified* TRC whose "validity" period (defined in the TRC itself) has begun and has
    not yet ended. Note: this does not consider the grace period of any following TRC.
1. __Active:__ a *valid* TRC that may still be used for verifying certificate signatures, i.e.,
    either the latest TRC or the previous one if it is still in its grace period. No more than two
    TRCs can be active at the same time for each ISD from the viewpoint of a relying party.
1. __Latest:__ the TRC with the highest version number known to the relying party.

Other qualifiers for TRCs include the following:

- __Initial:__ the first TRC of an ISD. It must have version 1 (version 0 being reserved to request
  the latest TRC).
- __Base:__ a TRC that defines the trust anchor for a TRC chain verification. An initial TRC is a
  special case of this. Each TRC references the version of the base TRC it uses as trust anchor. In
  a base TRC this reference is equal to its own version.
- __Inconsistent:__ verified TRCs with the same version number and the same ISD identifier with
  differing contents.
- __Expired:__ a TRC whose validity period has ended, or that has been replaced by an update whose
  grace period renders the previous TRC inactive.

### Types

Through out this document, the terms __string__, __integer__, __timestamp__ must be interpreted as
follows (unless specified otherwise):

- __string:__ UTF-8 string.
- __integer:__ All integers are unsigned.
- __timestamp:__ 64-bit integer indicating seconds since the Unix epoch.

## Design Goals

During normal operations, the CP-PKI should require minimal human intervention, and updating a TRC
should not interrupt network operation. Conversely, after a severe key compromise human involvement
is desired and even required in some circumstances (which can be enforced by using special
cryptographic keys stored in secure offline locations).

### Authenticity

It should be possible to determine whether any TRC or certificate is authentic. More sensitive
actions in the CP-PKI should have higher authentication requirements, i.e., in terms of key type
(offline vs. online) and number of entities involved.

### Resilience

The CP-PKI should be able to tolerate the compromise of a small number of keys and enable recovery
with minimal effort, i.e., without requiring a complete re-establishment of the trust roots of the
corresponding ISD.

It should also be possible for an ISD to recover (with more effort and human involvement) after some
or all of its voting ASes have been compromised. Otherwise, a severely compromised ISD would have to
get a new ISD number, renumber its entire ISD, invalidate all remote references to the old ISD
number, and the old number would be considered poisoned, forever.

### Isolation

The consequences of a key compromise or TRC update in a given ISD should be strictly limited to
communications with or within that ISD. Compromising any number of ASes in an ISD shouldn't allow
forging TRCs for other ISDs.

### Uniqueness

A TRC version must never change after it has been issued. Moreover, there should not exist multiple
valid TRCs with different contents for the same ISD and with the same version number; this kind of
behavior is considered malicious (commonly referred to as a "split-world attack" or "equivocation").

### Avoiding Circular Dependencies (between Verification and Communication)

Some PKI designs assume that entities can communicate freely with each other. This is not the case
with SCION, as it defines the very communication infrastructure upon which participants rely.
Therefore, one of the main challenges is to avoid circular dependencies, where a communication path
is necessary to establish authenticity and authenticity must be verified to establish a
communication path.

## Trust Model

In this document, "trust" must be interpreted as follows. A set of trust anchors is defined in each
node's trust store. Signatures that can be verified using trust anchors or using public keys
certified by trust anchors are considered valid, unless a restriction (such as expiration or
revocation) applies. Trust anchors often take the form of self-signed root certificates (also called
roots of trust). In the context of SCION the trust anchors are TRCs.

The two predominant trust models in today's Internet are monopolistic (single root of trust) and
oligopolistic (multiple roots of trust). Typically, in both models, some or all certification
authorities are omnipotent. That is, if their key is compromised, then the security of the entire
system collapses. Moreover, roots of trust are typically defined through independent self-signed
certificates. The SCION trust model is different in mainly two ways. First, no entity is omnipotent;
following the "isolation" design goal, the capabilities of ISDs (authentication-wise) are limited to
communication channels in which they are involved. Second, the trust roots of each ISD are
co-located in a single file, the TRC, which is co-signed by voting ASes of the ISD. The trust store
of each relying party hence consists of a list of TRCs.

## Primary ASes

An ISD is made up of a number of ASes. There is a set of attributes that each AS may have:

- __core:__ AS that has core links to other core ASes.
- __voting:__ AS that participates in and signs TRC updates.
- __authoritative:__ AS that is authoritative for TRCs and certificates for the local ISD.
- __issuing:__ AS that issues AS certificates to other ASes in the ISD.

__Primary AS:__ has at least one of the above attributes.

All ASes with one or more attributes are considered primary ASes, and are listed in the TRC, along
with their relevant keys. ASes without any of these attributes are not considered primary and must
not appear in the TRC.

## Overview of Keys and Certificates

Voting ASes have online and offline key pairs. Issuing ASes have issuing grant keys. Offline keys are
used for infrequent safety-critical operations that will require administrator involvement to cross an
air gap, while online voting and issuing grant keys are used for frequent automated operations that do
not require administrator involvement. The renewal of AS and Issuer certificates is an example of a
fully automated operation that occurs every few days and only requires issuing and issuing grant keys.

The tables below give an overview of the different keys and certificates used in the CP-PKI. The TRC
contains the offline and/or online keys of primary ASes and is signed with a quorum of voting keys
(online or offline, depending on the context); as such, it can be considered a self-signed root
certificate, except that multiple parties are involved. Online/offline voting and issuing grant keys
are included in TRCs while other keys are authenticated via certificates. All ASes (including the
primary ASes) use AS certificates to carry out their regular operations (such as signing beacons).
Issuing ASes hold an additional certificate whose only purpose is to authenticate (other ASes' and
their own) AS certificates.

### Table: Private Keys

| Name               | Notation          | Auth. ¹          | Validity ²  | Revocation  | Usage                       |
| ------------------ | ----------------- | ---------------- | ----------- | ----------- | --------------------------- |
| Offline voting key | `K_offline`       | TRC              | 5 years     | TRC update  | Sensitive TRC update        |
| Online voting key  | `K_online`        | TRC              | 1 year      | TRC update  | Regular TRC update          |
| Issuing grant key  | `K_issuing_grant` | TRC              | 1 year      | TRC update  | Signing issuer certificates |
| Issuing key        | `K_issuing`       | `C_issuer`       | 6 months    | Dedicated ³ | Signing AS certificates     |
| Encryption key     | `K_enc`           | `C_AS`           | 3 months    | Dedicated ³ | DRKey                       |
| Signing key        | `K_sign`          | `C_AS`           | 3 months    | Dedicated ³ | Signing CP messages         |
| Revocation key     | `K_rev`           | `C_issuer`,`C_AS`| 6/3 months  | Dedicated ³ | Revoke certificate          |

[¹]: Location of the corresponding (authenticated) public key.

[²]: Recommended usage period before key rollover (best practice).

[³]: As described in the [Best-Effort Certificate Revocation](#best-effort-certificate-revocation)
section below.

### Table: Certificates

| Name               | Notation      | Signed by         | Associated key    | Validity ⁴      |
| ------------------ | ------------- | ----------------- | ----------------- | --------------- |
| Issuer certificate | `C_issuer`    | `K_issuing_grant` | `K_issuing`       | 1 week          |
| AS certificate     | `C_AS`        | `K_issuing`       | `K_enc`, `K_sign` | 3 days          |

[⁴]: Recommended validity period (best practice).

## TRC Format

To encode the TRC we want a human and machine readable format with wide adoption. We opt for JSON as
it fulfills these requirements. However, even though there have been attempts to canonicalize JSON,
no such effort has made it into a widely adopted standard. We leverage [RFC 7515 JSON Web Signature
(JWS)](https://tools.ietf.org/html/rfc7515) for signing the TRC and encode the signed TRC in the JWS
JSON Serialization Representation (see [TRC Serialization](#trc-serialization)).

In the following sections, TRC refers to the payload of the full JWS signed TRC for simplicity. Note
that aspects relating to the end-entity and naming PKIs are ignored for the time being. They may be
introduced in a future version of the TRC format.

### Top-Level TRC Fields

This comprises all non-object values in the top level of the TRC.

- __isd:__ 16-bit integer. Unique and immutable ISD identifier.
- __version:__ 64-bit integer. TRC version, starts at 1. All TRC updates must increment
  this by exactly 1 (i.e., no gaps, no repeats).
- __base_version:__ 64-bit integer. Version of the base TRC that anchors this TRC chain.
  In a base TRC this is equal to *Version*.
- __description:__ string. Describes the ISD/TRC in human-readable form (possibly in multiple
  languages).
- __voting_quorum:__ 8-bit integer. Defines how many voting ASes from this ISD need to agree
  to be able to modify the TRC.
- __format_version:__ 8-bit integer. Version of the TRC format (currently 1).
- __grace_period:__ 32-bit integer. How long, in seconds, the previous unexpired version of
  the TRC should still be considered *active*, i.e., `TRC(i)` is still active until the following
  time has passed (or `TRC(i+2)` has been announced):

  `TRC(i+1).validity.not_before + TRC(i+1).grace_period`

  This formula allows the grace period to be adjusted according to the urgency, i.e., in a key
  compromise situation, it may be preferable to have a shorter grace period than during regular
  updates. A base TRC must have a grace period of zero. All other TRCs must have a grace period
  larger than zero.

  From a relying party's viewpoint, an updated TRC might not be available instantly since it has to
  propagate through beaconing first.

- __trust_reset_allowed:__ Boolean. Specifies whether a third party can announce a trust reset for
    this ISD.

### TRC Section: `validity`

The following fields must be used to determine whether a TRC is *valid* (not to be confused with
*active*).

- __not_before:__ timestamp. Time before which this TRC cannot be considered *valid*.
- __not_after:__ timestamp. Time after which this TRC will no longer be considered *valid*.

### TRC Section: `primary_ases`

This is an object that maps primary AS identifiers to their attributes and keys:

- __attributes:__ Set of AS attributes. Can be `authoritative`, `core`, `issuing`, and/or `voting`.
  The set of attributes cannot be empty as the AS would not be considered primary. An
  `authoritative` AS must be `core`.

- __keys:__ Object that maps key types (`issuing_grant`, `voting_online` or `voting_offline`)
  to an object with the following fields:
    - __key_version:__ 64-bit integer. Starts at 1, incremented every time this key is replaced.
    - __algorithm:__ string. Identifies the algorithm this key is used with.
    - __key:__ Base64-encoded string representation of the public key.

An AS that has no core links must not be a core AS. An authoritative AS must be a core AS (this
ensures it is reachable by other core ASes for bootstrap purposes). A voting AS is required to have
both offline and online voting keys. Non-voting ASes must not have offline or online voting keys.
An issuing AS is required to have an issuing grant key. Non-issuing ASes must not have an
issuing grant key.

### TRC Section: `votes`

This is an object that maps AS identifiers to a key type (`voting_online` or `voting_offline`).

The votes section lists all ASes that voted for the TRC update. They must hold the voting attribute
in the previous TRC. A vote counts as valid, if the JWS signed TRC contains a signature from the
specified AS with the specified key.

This section is included to prevent an attacker from simply changing the set of signatures on the
JWS signed TRC to come up with another valid TRC for the same ISD and Version number (compromising
"uniqueness") without consent from a voting quorum.

A base TRC is the start of a TRC update chain. Base TRCs do not carry any votes. Therefore, trust
is established in a different manner for base TRCs (see [TRC Bootstrapping](#trc-bootstrapping)).

### TRC Section: `proof_of_possession`

This is an object that maps AS identifiers to an array of key types.

New or updated keys sign the first TRC they appear in to show proof of possession. In a base TRC,
all keys need to show proof of possession and sign the TRC. We recommend that all keys be fresh in
a trust-reset TRC.

### TRC Invariants

The following are conditions that must hold true for every TRC:

1. `not_before < not_after`
1. `1 <= voting_quorum <= count(voting ASes)`
1. `1 <= count(issuing ASes)`
1. Each `voting` AS has an offline and online voting key.
1. Each `issuing` AS has an issuing grant key.
1. Each `authoritative` AS is a `core` AS.
1. No non-`voting` AS has an online or offline voting key.
1. No non-`issuing` AS has an issuing grant key.
1. `(base_version == version) <==> (grace_period == 0)` (Initial TRC or trust reset)
1. `(base_version == version) ==> All keys must attach proof of possession to TRC`

### Example of a TRC Payload

````json
{
    "isd": 1,
    "version": 23,
    "base_version": 1,
    "description": "Example ISD",
    "voting_quorum": 2,
    "format_version": 1,
    "grace_period": 18000,
    "trust_reset_allowed": true,
    "validity": {
        "not_before": 1510146554,
        "not_after": 1541682554
    },
    "primary_ases": {
        "ff00:0:110": {
            "attributes": ["authoritative", "core", "issuing", "voting"],
            "keys": {
                "issuing_grant": {
                    "key_version": 12,
                    "algorithm": "Ed25519",
                    "key": "PQCd00doU4nAFURE7Q9s/4nAFUJPQNaC7S..."
                },
                "voting_offline": {
                    "key_version": 34,
                    "algorithm": "Ed25519",
                    "key": "K3WE17Q9s/84djid00RREne6SJPQC7gpYS..."
                },
                "voting_online": {
                    "key_version": 22,
                    "algorithm": "Ed25519",
                    "key": "JvgaODTGiO84O3XdoU4nAFUQO43uTPfDcN..."
                }
            }
        },
        "ff00:0:120": {
            "attributes": ["core", "voting"],
            "keys": {
                "voting_offline": {
                    "key_version": 11,
                    "algorithm": "Ed25519",
                    "key": "+XjIxmREKXId2cu9cNEvqMeVjvfBhFMu66..."
                },
                "voting_online": {
                    "key_version": 1000000,
                    "algorithm": "Ed25519",
                    "key": "0lIsyTRewuHAhtnj2Gt3hVbnNF2wb+0rS..."
                }
            }
        },
        "ff00:0:130": {
            "attributes": ["authoritative", "core", "issuing"],
            "keys": {
                "issuing_grant": {
                    "key_version": 42,
                    "algorithm": "Ed25519",
                    "key": "o9V50Hja2ajyyJYRcAEjrcYCzty+iZFE2d..."
                }
            }
        }
    },
    "votes": {
        "ff00:0:110": "voting_offline",
        "ff00:0:120": "voting_offline"
    },
    "proof_of_possession": {
        "ff00:0:110": ["voting_online", "issuing_grant"],
        "ff00:0:120": ["voting_offline"]
    }
}
````

### TRC Serialization

A TRC is signed using the JWS standard and serialized using the General JWS JSON Serialization
Syntax [Section 7.2.1 of RFC 7515](https://tools.ietf.org/html/rfc7515#section-7.2.1).

The following fields must be present and no other must be set:

- __payload:__ The BASE64URL-encoded TRC payload described above.
- __signatures:__ JSON array of the signature objects.

The following fields must be present in the signature object and no other must be set:

- __protected:__ The BASE64URL(UTF8(metadata))-encoded metadata of the signature.
- __signature:__ The BASE64URL encoded JWS signature.

The following fields must be present in the metadata object and no other must be set:

- __alg:__ The signing algorithm to mitigate algorithm substitution attacks [Section 10.7 of RFC
  7515](https://tools.ietf.org/html/rfc7515#section-10.7).
- __crit:__ The following immutable array `["type", "key_type", "key_version", "as"]`
- __type:__ The type of signature. (`proof_of_possession` or `vote`)
- __key_type:__ The signing key type (`issuing_grant`, `voting_online` or `voting_offline`).
- __key_version:__ The signing key version.
- __as:__ The ISD-AS of the signing AS.

An example of how the TRC is serialized and signed can be found in the
[appendix](#trc-serialization-example).

The signature input is in accordance with the RFC: `ASCII(protected || '.' || payload)`

The hash that is announced during beaconing is calculated over `ASCII(payload)`. This is necessary,
since the order of the keys when serializing JSON is not specified and cannot be relied on. However,
since the TRC payload explicitly states all expected signatures, and those signatures can only be
created with the respective keys, the "uniqueness" property cannot be violated.

## TRC Updates

In general, the TRC validity period is shorter than the validity of the keys it authenticates. Thus,
TRCs are regularly updated to cover the full key validity period. In addition to these regular
updates, sensitive updates, such as changes to the keys of a primary AS, can occur.

In this section we describe how TRCs must be verified. This includes a verification of the TRC chain
as well as other basic validations. Note, however, that a *verified* TRC is not necessarily *valid*
or *active*.

A TRC update involves two TRC versions with the same ISD identifier: the "previous" version and the
"updated" version. The previous TRC version is equal to the updated TRC version - 1. Verification of
the updated version is done against the previous TRC. To respect the uniqueness property, there is
exactly one previous TRC for all non-base TRCs.

The update votes can still be verified, even after the previous TRC's validity period has passed.
This allows entities to verify the chain even if any of the previous TRCs in the chain have expired.

Trust resets are not considered TRC updates, since they set a new trust anchor. They are described
later in this document.

For any kind of update, the following conditions must be met:

- The [TRC Invariants](#trc-invariants) must hold.
- The `isd` identifier field is immutable.
- The `trust_reset_allowed` field is immutable.
- The `version` field must be equal to the previous version + 1.
- The `base_version` must be equal to the base version of the pervious TRC.
- The `grace_period` of the TRC must not be 0. (A TRC with a grace period of 0 indicates a trust
  reset)
- The `not_before` validity field must be in the range spanned by the validity fields of the previous
  TRC.
- There must only be votes by voting ASes of the previous TRC.
- The number of votes must be greater than or equal to the `voting_quorum` parameter of the previous
  TRC.
- Keys can be updated only with a strictly increasing `key_version` number. In case the key is
  changed, the `key_version` must be the previous version + 1. In case the `key_version` remains the
  same, the key must not change. This holds true over all TRCs since the base TRC. I.e. if an AS is
  demoted and later promoted again, the key version continues where it left off before. This must be
  ensured by all signing entities.

  Relying parties must check the `key_version` is correct in the updated TRC, if the previous TRC
  already contains a key of the given type for that primary AS. If not, relying parties are free to
  ignore the check.
- Any key that was not present in the previous TRC must show proof of possession by signing the new
  TRC. This guarantees that any key present in any version of the TRC has been used to produce at
  least one signature in the TRC's history, which shows a proof of possession (PoP) of the
  corresponding private key (considered a good practice in such a context, see the appendix).
  These signatures are distinct from votes and do not count towards the quorum.

### Regular TRC Update

In a regular update, the `voting_quorum` parameter must not be changed. In the `primary_ases` section,
only the issuing grant and online voting keys can change. No other parts of the `primary_ases` section
may change.

- All votes from ASes with unchanged online voting keys must be cast with the online voting key.
- All ASes with changed online voting keys must cast a vote with their offline voting key.

### Sensitive TRC Update

A sensitive update is any update that is not "regular" (as defined above). The following conditions
must be met:

- All votes must be issued with the offline voting key authenticated by the previous TRC.

Compared to the regular update, the restriction that voting ASes with changed online voting key must
cast a vote is lifted. This allows replacing the online and offline voting key of a voting AS that
has lost its offline voting key without revoking the voting status.

## TRC Update Dissemination

A TRC update must be distributed amongst all authoritative ASes in that ISD, and they must switch to
it as the latest version in a synchronized fashion. That is, when querying two distinct
available authoritative ASes for the latest TRC version, they must reply with the same version
modulo some minor clock skew.

ASes inside that ISD must only announce the new TRC after the available authoritative ASes have
switched their view of the latest TRC version. This can easily achieved by having authoritative ASes
switch the latest on the `validity.not_before` time, since SCION requires synchronized clocks.

TRC updates are disseminated via SCION's beaconing process. If the TRC version number within a
received beacon is higher than the locally stored TRC, the beacon server sends a request to the
beacon server that sent the beacon. After a new TRC is accepted, it is submitted by the beacon
server to a local certificate server. Path servers and end hosts learn about new TRCs through the
path-segment registration and path lookup processes, respectively.

All entities within an ISD must have a recent TRC of their own ISD. On startup, all servers and end
hosts obtain the missing TRCs (if any, from the TRC they possess to the latest TRC) of their own ISD
from a certificate server.

### Getting a TRC

````python
getVerifiedTRC(isd, version):
    if version <= 0:
        return nil
    trc = trustStoreQueryTRC(version)
    if trc != nil:
        return trc
    previous = getVerifiedTRC(isd, version - 1)
    trc = downloadTRC(isd, version)
    if verifyTRC(trc, previous) == true:
        return trc
    return nil
````

The above code is simplified and does not implement the "version 0 means latest" feature.

## TRC Trust Reset

Aside from initial TRCs, trust anchors can be re-established with a trust reset. Typically, a trust
reset is needed when at least a quorum of voting ASes' online or offline voting keys have been compromised,
or when a quorum can no longer be met. A trust reset is a worst case scenario, that is unlikely to
happen. It is not considered a TRC update and may involve human intervention if necessary. A Trust
reset is only permissible if `trust_reset_allowed` is set to `true`; otherwise, no trust reset is
possible, and the ISD can only be re-established with a new ISD identifier.

When resetting the trust anchor, the [TRC Invariants](#trc-invariants) must still hold. We describe
multiple different mechanisms that allow handling trust resets in [TRC
Bootstrapping](#trc-bootstrapping) and setting new trust anchors.

The new base TRC is allowed to introduce a version number gap. If an ISD is severely compromised,
and the attacker can issue new TRCs, this allows the ISD to get a head start. To taint the network,
the attacker has to distribute the TRC first. If the new base TRC does violate the version
uniqueness property, human intervention is necessary to rectify the situation by pruning the
maliciously issued TRC chain to ensure uniqueness.

## Certificate Format

Similarly to TRCs, AS certificates are serialized and signed using JWS. Certificates only carry one
signature and will be serialized using the Flattened JWS JSON Serialization Syntax (see [Certificate
Serialization](#certificate-serialization)).

In the following sections, certificate refers to the payload of the full JWS signed certificate for
simplicity. Certificates are uniquely identified by the `(subject, version)`-pair.

There are two types of certificates: __Issuer certificates__ and __AS certificates__. An AS
certificate is authenticated by exactly one Issuer certificate. An Issuer certificate is signed by
exactly one issuing key. This issuing key is authenticated by one or multiple (in the case of TRC
update) TRCs.

### Top-Level Certificate Fields

- __subject:__ string. ISD and AS identifiers of the entity that owns the certificate and the
  corresponding key pair.
- __version:__ 64-bit integer. Certificate version, starts at 1.
- __format_version:__ 8-bit integer. Version of the TRC/certificate format (currently 1).
- __description:__ UTF-8 string. Describes the certificate and/or AS.
- __certificate_type:__ string. Indicates whether the subject is allowed to issue certificates
  for other ASes. Can be either `issuer` (can issue certificate) or `as` (cannot). This field also
  determines the contents of the __issuer__ section.
- __optional_distribution_points:__ Array string. Additional certificate revocation distribution
  points formatted as ISD-AS string. They must be authoritative in their ISD.

### Certificate Section: `validity`

The following fields must be used to determine whether a certificate is valid.

- __not_before:__ timestamp. Time before which this Cert cannot be used to verify signatures.
- __not_after:__ timestamp. Time after which this Cert may no longer be used to verify signatures.

The full validity period must be covered by the validity period of the signing certificate/TRC.

### Certificate Section: `keys`

This is an object that maps the type of key (`issuing`, `encryption`, `signing`, or `revocation`) to
the algorithm and the key.

- __keys:__ Object that maps key types to an object with the following fields:
    - __algorithm:__ string. Identifies the algorithm this key is used with.
    - __key:__ Base64-encoded string representation of the public key.
    - __key_version:__ 64-bit integer. Starts at 1, incremented every time the key is replaced.

The following table shows what keys are authenticated by the different certificate types. The key
notation is the same as in the [private keys table](#table-private-keys).

| Key Type       | Issuer Certificate      | AS certificate      |
| -------------- | ----------------------- | ------------------- |
| `issuing`      | required (`K_issuing`)  | illegal             |
| `encryption`   | illegal                 | required (`K_enc`)  |
| `signing`      | illegal                 | required (`K_sign`) |
| `revocation`   | optional (`K_rev`)      | optional (`K_rev`)  |

### Certificate Section: `issuer`

The contents depend on the certificate type:

#### AS Certificate

- __isd_as:__ string. ISD and AS identifiers of the entity that signed this certificate. The issuer must
  be in the same ISD as the subject of this certificate.
- __certificate_version:__ 64-bit integer. The certificate version of the Issuer certificate.

#### Issuer Certificate

- __trc_version:__ 64-bit integer. Version of the TRC the issuer used when signing the certificate.
  Note that a certificate can still be valid and verifiable even if the TRC version specified is no
  longer active, so long as the issuing AS still has the same issuing key in any of the active TRC
  versions.

The issuer certificate is self-signed with the `issuing_grant` key in the TRC. Thus, the issuer is the
same as the certificate subject and does not need to be specified.

### Example of an AS Certificate Payload

````json
{
    "subject": "1-ff00:0:120",
    "version": 1,
    "format_version": 1,
    "description": "AS certificate",
    "certificate_type": "as",
    "validity": {
        "not_before": 1480927723,
        "not_after": 1512463723
    },
    "keys": {
        "encryption": {
            "algorithm": "curve25519",
            "key": "Gfnet1MzpHGb3aUzbZQga+c44H+YNA6QM7b5p00dQkY=",
            "key_version": 21
        },
        "signing": {
            "algorithm": "Ed25519",
            "key": "TqL566mz2H+uslHYoAYBhQeNlyxUq25gsmx38JHK8XA=",
            "key_version": 21
        }
    },
    "issuer": {
        "isd_as": "1-ff00:0:130",
        "certificate_version": 6
    }
}
````

### Example of an Issuer Certificate Payload

````json
{
    "subject": "1-ff00:0:130",
    "version": 6,
    "format_version": 1,
    "description": "Issuer certificate",
    "certificate_type": "issuer",
    "validity": {
        "not_before": 1442862832,
        "not_after": 1582463723
    },
    "keys": {
        "issuing": {
            "algorithm": "Ed25519",
            "key": "SKx1bhe3mh4Wl3eZ1ZsK1MwZwsSfcwvyn4FSI9yTvDs=",
            "key_version": 72
        }
    },
    "issuer": {
        "trc_version": 2,
    }
}
````

### Certificate Serialization

A certificate is signed using the JWS standard and serialized using the Flattened JWS JSON
Serialization Syntax [Section 7.2.2 of RFC 7515](https://tools.ietf.org/html/rfc7515#section-7.2.2).

The following fields and no other must be present:

- __payload:__ The BASE64URL-encoded certificate payload described above.
- __protected:__ The BASE64URL(UTF8(metadata))-encoded metadata of the signature.
- __signature:__ The BASE64URL encoded JWS signature.

The metadata differs when signing AS and Issuer certificates.

For AS certificates, the following fields and no other must be present in the metadata object:

- __alg:__ The signing algorithm to mitigate algorithm substitution attacks [Section 10.7 of RFC
    7515](https://tools.ietf.org/html/rfc7515#section-10.7).
- __crit:__ The following immutable array `["type", "certificate_version", "isd_as"]`
- __type:__ Must be the string `"certificate"`, to indicate the public key is authenticated by an
    issuer certificate.
- __certificate_version:__ The version of the Issuer certificate.
- __isd_as:__ The ISD-AS of the signing AS.

For Issuer certificates, the following fields and no other must be present in the metadata object:

- __alg:__ The signing algorithm to mitigate algorithm substitution attacks [Section 10.7 of RFC
  7515](https://tools.ietf.org/html/rfc7515#section-10.7).
- __crit:__ The following immutable array `["type", "trc_version"]`
- __type:__ Must be the string `"trc"`, to indicate the public key is authenticated by a TRC.
- __trc_version:__ The trc version.

An example of how a certificate is serialized and signed can be found in the
[appendix](#chain-serialization-example).

The signature input is in accordance with the RFC: `ASCII(protected || '.' || payload)`

## Certificate Chain

Certificate chains consist of an Issuer and an AS certificate. They are uniquely identified by the
AS certificate's `(subject, version)`-pair, since the AS certificate references the Issuer
certificate. Thus, for any given AS certificate there is exactly one corresponding certificate
chain.

The certificate chain is represented as a JSON array with the first entry being the serialized and
signed Issuer certificate and the second entry being the serialized and signed AS certificate.

### Example of a serialized Certificate Chain

````json
[
    {
        "payload": "1bhe3mh4Wl3eZ1ZsK1MwZwsSfcbZQ...",
        "protected": "wo/hPSHgBIh8J5nHPe3mh4W4FSI...",
        "signature": "H+uslHYoAYBhQeNlyxUq23aUxzb..."
    },
    {
        "payload": "1bhe3mhsK1MwZJ5nHPeZ1MwZwsSfc...",
        "protected": "HPe3mQsK1l3eZnHPe323mh4xUq2...",
        "signature": "851kmxSPfkszl23USfbMwZwsSfc..."
    }
]
````

## Signature Validation based on Certificate Chains

When validating signatures based on certificate chains, the following must be checked:

- The signature can be verified with the public key authenticated by the AS certificate of a
  verified certificate chain.
- The current time falls within the validity period of the certificate chain.
- No revocation has been cached for either certificate in the chain.
  How often a relying party updates the cache depends on their own policy.
- The certificate chain is authenticated by a currently active TRC. This means the issuing grant key
  that was used to sign the Issuer certificate must be authenticated by a currently active TRC. The
  active TRC's version must be greater than or equal to the `trc_version` specified in the Issuer
  certificate.

  This allows signature validation to succeed during the grace period of a TRC update with a
  modified issuing grant key.

## Certificate Chain Dissemination

Certificate chains are issued by an `issuing` AS upon request. As certificates are short lived, this
is an automated process. Before an AS may use a certificate chain, it must register it with all
authoritative ASes of its ISD. If the automatic registration process fails due to an unavailable
authoritative AS, an operator may manually choose to start using the issued certificate chain.
However, they must ensure the certificate chain is registered as soon as possible with all
authoritative ASes of its ISD.

Certificate chains are used to sign beacons and path-segments. Similar to TRC dissemination, when a
beacon server receives an unknown certificate chain version, it sends a request to the sending
beacon server. When a path server gets a path segment with an unknown chain, it requests the missing
certificate chain from the entity that provided the segment. This could either be the beacon server,
or a remote path server. End hosts query their local certificate server for missing certificate
chains.

### Getting an AS Certificate Chain

````python
getVerifiedChain(isd, as, version):
    chain = trustStoreQueryChain(isd, as, version)
    if chain != nil:
        return chain
    chain = downloadChain(isd, as, version)
    trc = getVerifiedTRC(isd, chain[0].issuer.trc_version)
    if verifyChain(cert, trc) == true:
        return cert
    return nil
````

### Certificate Chain Verification

When verifying a certificate chain, the following must be checked:

- The signature of the AS certificate can be verified with the public key authenticated by the
  Issuer certificate
- The signature of the Issuer certificate can be verified with the issuing grant key in the
  referenced TRC.
- The AS certificate validity period is covered by the Issuer certificate period.
- The Issuer certificate validity period is covered by the referenced TRC validity period.

## Best-Effort Certificate Revocation

With a validity on the order of days, AS certificates can be considered short-lived. Nevertheless,
an attack window of several days is too large for mission-critical operation. Therefore, the CP-PKI
needs a system for quickly revoking AS and issuer certificates. The revocation status must be
cacheable and efficient to distribute. Also, propagation of revocations must not hinder the
availability of the infrastructure.

The number of ASes in SCION will most likely exceed the number of ASes in the current Internet by a
few orders of magnitude, which will result in a large number of certificates. However, because
certificates are short-lived and because stale revocations can be discarded, revocation lists will
remain small or empty most of the time.

### Revocation Notes

A revocation note attests that a certificate is revoked. A revocation note is either signed by the
signing key contained in the revoked certificate, or a separate `revocation` key. The `revocation`
public key may also be specified in the revoked certificate, in which case the corresponding private
key must be stored offline and used to sign the revocation note instead of the regular signing key.
The revocation key may also be used to request a new certificate from an issuer. It may be stored at
the issuer or a third party, such that they can revoke the certificate in case the certificate's
subject loses the revocation key. This requires a certain level of trust between the subject and the
third party.

#### Revocation Note Format

The revocation note is simply a signature over the ASCII string `Revocation Note: Type={{type}}
IA={{ia}} Version={{version}} TS={{timestamp}}`, where `{{type}}` is replaced by the
`certificate_type`, `{{ia}}` is replaced by the subject, `{{version}}` is replaced by the version
of the revoked certificate, and `{{timestamp}}` is a timestamp when the revocation was issued.

### Revocation Note Distribution

Each authoritative AS is a revocation note distribution point. ASes that want to revoke their
certificate must register the revocation note with all authoritative ASes of their ISD. If the
certificate has configured optional distribution points, the AS must distribute the note to them as
well.

Distribution points keep a data structure that allows querying new revocation notes that have been
registered after the provided time. The signed response contains the revocation notes including the
time that the revoked certificates expires. Additionally, the distribution points can be queried
about a specific certificate.

ASes periodically query at least one distribution point of all valid certificates in their trust
store. Relying parties ask their local certificate server about the state of a certificate. In
case they do not trust their certificate server for this, they can query the distribution points
themselves.

A distribution point must only be queried if it is an authoritative AS in the ISD.

### Revocation Note Registration

In case the AS notices a key compromise, it issues the revocation note and sends it with the revoked
certificate to all the specified distribution points. If possible, the AS should fetch a certificate
with updated keys before revoking the compromised one. Otherwise remote ASes will no longer be able
to reach the AS, until a new certificate is fetched and installed out-of-band.

Revoking an Issuer certificate has severe implications. All certificate chains that contain it will
no longer be considered valid. Thus, a large portion of an ISD might be unreachable for some period
of time. Operators should coordinate and prepare before revoking an issuer certificate.

### Best-Effort

Certificate revocation stands in stark contrast with availability. If relying parties only
considered a certificate valid after querying the corresponding distribution point, then there would
be a circular dependency between verifying paths to the distribution points and having paths to the
distribution point. To avoid this circular dependency, revocations are to be considered on a
best-effort basis. During regular operation, the revocation distribution points will be
available and certificates are revoked in a short amount of time. Also, an AS can take advantage of
the `optional_distribution_points` field in the AS cert to nominate distribution points that are
geographically diverse to mitigate availability issues.

If any of the distribution points contains a revocation note, the certificate is considered revoked
and should no longer be considered valid. In case of an issuer certificate, this means all
certificate chains containing it will also be considered invalid.

## Trust Material Sources

When dealing with cryptographic material, operators should have a point to contact to do certain
kinds of queries. Authoritative ASes are required to keep all certificates issued inside their ISD.
Queries such as asking for the newest TRC should be sent to an authoritative AS. All other ASes are
required to have the trust material to verify all messages they serve. For example, an AS must have
all the certificate chains needed to verify the path segments it serves.

The subjects of certificate chains must register all freshly issued chains with all authoritative
primary ASes in the local ISD. The same holds true for the subjects of issuer certificates.

If an authoritative AS has been unavailable, it must not serve authoritative queries until it has
synchronized with the other authoritative ASes. Examples of authoritative queries are:

- Issuer certificate request with negative response.
- Certificate chain request with negative response.
- Newest certificate chain for given AS.
- Newest TRC for this ISD.

The following rules define trust material lookup in the different services:

__Path Server:__ When verifying path segments, query the sending beacon/path server.

__BeaconServer:__ When verifying beacons, query the sending beacon server.

__Certificate Server:__ The following table shows where a certificate server fetches the material
based on which type of AS it resides in.

| AS type           | Local ISD TRC | Remote ISD TRC | ISD Local Chain | Remote Chain   |
| ----------------- | ------------- | -------------- | --------------- | -------------- |
| Authoritative     | n/a ¹         | remote auth AS | n/a ¹           | remote auth AS |
| Non-authoritative | local auth AS | remote auth AS | local auth AS   | remote auth AS |

[¹]: An authoritative AS should have all trust material for their local ISD available.

__others:__ All other requests are sent to the local certificate server that recursively fetches the
certificates according to the table.

## TRC Bootstrapping

Base TRCs are trust anchors and thus axiomatically trusted. All nodes must be pre-loaded with at
least the current base version TRC of their own ISD, which builds the trust anchor.

In the following, we discuss multiple options for distributing TRC base versions of other ISDs and
adding them to the trust store of relying parties. A trust reset is essentially the same problem as
distributing the initial TRC version, and can be solved with the same mechanisms.

Out of the three options presented here, we recommend the "TRC Attestation" method since it provides
a reasonable trade-off between security and ease of operation. The other methods are of academic
interest, but either offer more limited availability or worse security properties. Independent of
the method that an ISD uses for TRC bootstrapping, it is required to support TRC attestation for
queries it receives from other ISDs.

### Manual Mode

In the manual mode, the operators are responsible for adding all TRCs manually to their trust store.
They can receive TRCs through multiple channels (e.g., through out-of-band mechanisms or by
discovering them during the beaconing process).

### Trust On Multi-Announcement (TOMA)

In the trust on multi announcement (TOMA) mode, initial TRCs and trust reset TRCs that are
discovered during the beaconing process are put into quarantine for a specified amount of time. If
during this quarantine period, the TRCs have been received on a pre-defined number of distinct paths
with exactly the same content, the TRC is trusted and added to the trust store.

Alternatively, the quarantined TRC can be sent to an operator for review who then accepts the TRC.
This merges the TOMA and manual methods to provide easier operations, as it limits operator
involvement.

TOMA is only applicable for core ASes, since they are the only ones that are able to receive beacons
with unknown TRCs. In fact, some core ASes might need to band together, in order to observe enough
distinct paths.

Non-core ASes and end hosts need an authentic channel to the core in order to fetch newly discovered
TRCs. However, this can easily be provided, since the routing inside an ISD only depends on the
availability of the local TRC.

### TRC Attestation

The previously mentioned methods imply a large operational overhead. Requiring human involvement for
may not be desirable, or may not even be feasible. With the TRC Attestation method, human
involvement is reduced to a minimum.

A numbering authority will coordinate the attribution of identifiers to ISDs globally. It is likely,
however, that this authority will delegate and allocate ISD ranges to regional authorities, which
will then assign specific identifiers to ISDs in their region. These regional authorities act as the
Regional Attestation Authority (RAA).

An __Attestation__ is issued for every base TRC and indicates to any relying party that the base TRC
is considered the trust anchor for the respective ISD at the time of signing. Thus, whenever an ISD
registers itself with the regional numbering authorities, it simultaneously obtains an attestation
for bootstrapping purposes. Additionally, whenever an ISD is forced to perform a trust reset, a new
attestation must be obtained.

Attestations are used by relying parties to validate initial or trust-reset TRCs of remote ISDs.
They are stored in the trust store and are considered first order citizens. When a relying parties
encounters an unknown base TRC during a TRC request, it fetches the attestation from the same node.
Thus, even infrastructure nodes operating in manual, TOMA or any other mode must be able to provide
attestations for every base TRC in their store. In fact, they should include attestation
verification into their decision process for added security.

Regional numbering authorities must maintain an append-only log of base TRCs and attestations in
their ISD range(s) for auditability. This also allows all entities to quickly discover new base
TRCs, either caused by a new ISD joining the network or by a trust reset. Additionally, the RAAs
manage an append-only log of all TRCs in their ISD range. RAAs discover new TRCs by periodically
fetching the newest TRCs in their ISD range.

Even with an append-only log, a split-world attack is still possible: a RAA could provide different
attestations for the same identifier to different clients. For this reason, TRC hashes must be
included into beacons and verified by other ASes, see
[appendix](#beacon-format-as-entry-modification). This effectively runs a gossip protocol among ASes
and allows them to detect inconsistent TRCs.

A RAA can only issue attestations for trust resets if the initial TRC has set `trust_reset_allowed`
to true. This prevents RAAs from triggering a "kill switch" on ISDs who decided to set this flag to
`false`. However, this also burns an ISD number in case a large amount of the offline keys of that
ISD are lost or compromised. We stress that this is a disastrous failure case and is very unlikely
to occur.

Attestations are signed by the RAA and are verifiable using the TRC Attestation Authority Config
(TAAC). Every RAA has their own TAAC. The structure is very similar to a TRC. The TAAC contains a
set of attestation keys that are used to verify attestations, and a set of offline keys used to sign
new TAAC versions.

#### TRC Attestation Format

Attestations carry only one signature and will be serialized using the Flattened JWS JSON
Serialization Syntax [Section 7.2.2 of RFC 7515](https://tools.ietf.org/html/rfc7515#section-7.2.2).

The following fields and no other must be present in the metadata object:

- __payload:__ The BASE64URL-encoded serialized base TRC.
- __protected:__ The BASE64URL(UTF8(metadata))-encoded metadata of the signature.
- __signature:__ The BASE64URL encoded JWS signature.

The following fields and no other must be present in the metadata object:

- __alg:__ The signing algorithm to mitigate algorithm substitution attacks [Section 10.7 of RFC
    7515](https://tools.ietf.org/html/rfc7515#section-10.7).
- __crit:__ The following immutable array `["taa_name", "key_id", "key_version", "timestamp"]`
- __taa_name:__ The name of the TRC attestation authority.
- __key_id:__ The attestation key identifier.
- __key_version:__ The attestation key version.
- __timestamp:__ 64-bit integer in seconds since Unix epoch.

#### TRC Attestation Authority Config (TAAC)

The TRC Attestation Authority Config (TAAC) is represented using JWS JSON Serialization. The
structure and content of a TAAC is similar to that of a TRC. There are a few (logical) groups of
data in it, explained in the following sections.

##### Top-Level TAAC Fields

This comprises all non-object values in the top level of the TAAC.

- __taa_name:__ UTF-8 string. Name of the TRC attestation authority.
- __taac_version:__ 64-bit integer. TAAC version, starts at 1. All TAAC updates must
    increment this by exactly 1 (i.e., no gaps, no repeats).
- __alias:__ String array. List of all ISD-AS identifiers the TAA is reachable under.
- __voting_quorum:__ 8-bit integer. Defines how many offline keys are necessary to update
  the TAAC.
- __grace_period:__ 32-bit integer. How long, in seconds, the previous unexpired version of
  the TAAC can still be used to validate attestations (same as in TRC). `TAAC(i)` is still active
  until the following time has passed (or `TAAC(i+2)` has been announced):

    `TAAC(i+1).validity.not_before + TAAC(i+1).grace_period`

##### TAAC Section: `validity`

The following fields must be used to determine whether a TAAC is *valid*.

- __not_before:__ timestamp. Time before which this TAAC cannot be considered *valid*.
- __not_after:__ timestamp. Time after which this TAAC will no longer be considered *valid*.

##### TAAC Section: `offline_keys`

This is an object that maps offline key identifiers to the keys. Offline keys are used to verify
TAAC updates.

- __key_version:__ 64-bit integer. Starts at 1, incremented every time this key is
  replaced.
- __algorithm:__ String. Identifies the algorithm this key is used with.
- __key:__ Base64-encoded string representation of the public key.

##### TAAC Section: `attestation_keys`

This is an object that maps attestation key identifiers to the keys. Attestation keys are used to
verify Attestations.

- __key_version:__ 64-bit integer. Starts at 1, incremented every time this key is
  replaced.
- __algorithm:__ String. Identifies the algorithm this key is used with.
- __key:__ Base64-encoded string representation of the public key.

#### TAAC Invariants

The following are conditions that must hold true for every TAAC:

1. `not_before < not_after`
1. `0 < voting_quorum <= count(offline_keys)`
1. `count(attestation_keys) >= 1`
1. `grace_period > 0`
1. `count(alias) > 0` and all entries are valid ISD-AS strings.

#### Example of TAAC Payload

````json
{
    "taa_name": "RegionalTAA-1",
    "taac_version": 2,
    "alias": ["1-ff00:0:110", "2-ff00:0:220"],
    "voting_quorum": 9,
    "grace_period": 2592000,
    "validity": {
        "not_before": 1577836800,
        "not_after": 1893456000
    },
    "offline_keys": {
        "off_key_1": {
            "key_version": 1,
            "algorithm": "Ed25519",
            "key": "VJRXxT2nWrHFT9qKwlG8z3lBeb/VcLQTzA..."
        },
        "off_key_2": {
            "key_version": 1,
            "algorithm": "Ed25519",
            "key": "PkdxgZiODO/glKHsYcR6m9k7SoSxsja86T..."
        },
        "off_key_3": "..."
    },
    "attestation_keys": {
        "att_key_1": {
            "key_version": 2,
            "algorithm": "Ed25519",
            "key": "ObjSwF0YDo0Eg/KFxgXJkh2IWv7OBRa1aF..."
        }
    }
}
````

#### TAAC Serialization

A TAAC is signed using the JWS standard and serialized using the General JWS JSON Serialization
Syntax [Section 7.2.1 of RFC 7515](https://tools.ietf.org/html/rfc7515#section-7.2.1).

The following fields and no other must be present:

- __payload:__ The BASE64URL-encoded TAAC payload described above.
- __signatures:__ JSON array of the signature objects.

The following fields and no other must be present in the signature object:

- __protected:__ The BASE64URL(UTF8(metadata))-encoded metadata of the signature.
- __signature:__ The BASE64URL encoded JWS signature.

The following fields and no other must be present in the metadata object:

- __alg:__ The signing algorithm to mitigate algorithm substitution attacks [Section 10.7 of RFC
  7515](https://tools.ietf.org/html/rfc7515#section-10.7).
- __crit:__ The following immutable array `["key_id", "key_type", "key_version"]`
- __key_id:__ The offline key identifier.
- __key_type:__ The signing key type (`attestation` or `voting_offline`).
- __key_version:__ The signing key version.

The signature input is in accordance with the RFC: `ASCII(protected || '.' || payload)`

#### TAAC Update

Similar to TRCs, a TAAC can be updated. The updates are very infrequent, on the order of years. When
an update is issued, each RAA has to issue new attestation for all newest base TRCs of every ISD in
its range that were signed with an updated/removed attestation key. Upon discovering a new TAAC,
infrastructure nodes need to fetch the new attestations for all newest base TRCs in their trust
store that were signed with a removed attestation key. This allows new nodes to bootstrap TRC chains
after the TAAC update grace period has passed.

The following conditions must hold for an update to be considered valid:

- The [TAAC invariants](#taac-invariants) must hold.
- The `taa_name` identifier field is immutable.
- The `taac_version` field must be equal to the previous version + 1.
- The `not_before` validity field must be in the range spanned by the validity fields of the
  previous TAAC.
- There must be a number of signatures from offline keys from the previous TAAC greater than or
  equal to the `voting_quorum` parameter in the previous TAAC.
- Any key that was not present in the previous TAAC must sign the new TAAC to show PoP.

#### TAAC Dissemination

Contrary to TRCs, TAACs are not discovered through the beaconing process. Even though attestations
are first class citizens, we do not want to force ASes to use them for their internal decision
making. The relying parties periodically check whether a new TAAC exists. This is done in a
hierarchical manner. Core ASes query the RAA directly. Non-core query their core. End hosts query
the local AS. To prevent entities from hiding TAAC updates, the RAA periodically issues a "proof of
non-existence". This proof is signed with a attestation key of the newest TAAC and declares that for
a given period of time, there is no newer TAAC.

#### Internet Reboot

Assuming the TAAC stays the same, a full Internet reboot with completely new TRCs is feasible with
few human interventions. The ISDs that host the RAAs will start initially to beacon. All adjacent
ISDs gain connectivity, since the new TRC can be verified based on the attestations. Thus, the
adjacent ISDs can request a trust reset, get the new attestation and start disseminating with the
new TRC. Connectivity then spreads further, until the full Internet is connected again.

The human intervention in this process limits itself to agreeing on a new TRC inside an ISD, and at
the RAA to accept trust resets. Notice, end hosts do not require any human interaction.

#### Trade-offs

With the attestation approach, we reduce the amount of necessary trusted files to the TAACs. On the
other hand, this also increases the impact in case of a key compromise. However, AS operators can
choose their own bootstrapping method according to their security and trust model.

Note that attestations are only used for bootstrapping, and trust resets after catastrophic events
that involved multiple AS offline voting key compromises. During normal operation and non-catastrophic
key compromises, the RAAs are not involved. ISDs can update their TRCs freely, without the consent
or attestation of RAAs. This limits the power that an RAA holds. Misbehavior on the RAA's part is
easily discoverable, as it is limited to issuing false trust resets.

## Appendix

### Beacon Format (AS Entry) Modification

This document proposes the addition of the following fields to beacons (in AS entries,
specifically):

- Hash algorithm
- TRC hash

ASes must treat these new fields as follows. When creating an AS entry, the hash of the latest TRC
and the algorithm used to compute that hash must be put into the AS entry. When receiving a beacon,
all AS entries must be verified; this includes verifying the TRC hashes, as follows (in pseudocode):

````python
verifyBeaconHashes(beacon):
    for each ASEntry in beacon:
        TRC = getVerifiedTRC(ASEntry.ISD, ASEntry.TRCVersion)
        if ASEntry.TRCHash != hash(TRC, ASentry.HashAlgo)
            return false
    return true
````

If the above verification returns `false`, then the beacon is dropped. The `getVerifiedTRC` function
is defined below. Note that it can return `nil` (in which case the verification fails).

Although this mechanism in itself does not guarantee uniqueness, it helps detecting inconsistent
TRCs with little overhead.

### Proof of Possession (PoP)

Evidence that an entity whose public key is known has access to the corresponding private key is
called proof of possession (PoP) of a private key. PoP is important for guaranteeing authenticity
and non-repudiation. For example, suppose Alice has a private key SK and its corresponding public
key PK. Alice has a certificate containing PK. Alice uses SK to sign a transaction T. Without PoP,
Mallory could get a certificate containing the same public key PK. There are two issues: Mallory
could claim to have been the real signer of T, and Alice can falsely deny signing T, claiming that
it was Mallory instead who signed the transaction [RFC 4211].

### TRC Serialization Example

In the following, the serialization of the TRC is described. As the TRC payload, we use the example
from above.

````py

def b64url(input: bytes) -> str:
    return base64.urlsafe_b64encode(input).decode().rstrip('=')

############################################
# Metadata serialization
############################################
# First we create the protected headers for 1-ff00:0:110 and 1-ff00:0:120.
# The online voting key of 1-ff00:0:110 is updated, and must thus sign the new
# version.

offline_110 = """
{
    "alg": "Ed25519",
    "crit": ["type", "key_version", "as"]
    "type": "voting_offline"
    "key_version": 34,
    "as": "1-ff00:0:110"
}
"""
offline_110_enc = b64url(offline_110.encode('utf-8'))

online_110 = """
{
    "alg": "Ed25519",
    "crit": ["type", "key_version", "as"]
    "type": "voting_online"
    "key_version": 22,
    "as": "1-ff00:0:110"
}
"""
online_110_enc = b64url(online_110.encode('utf-8'))


offline_120 = """
{
    "alg": "Ed25519",
    "crit": ["type", "key_version", "as"]
    "type": "voting_offline"
    "key_version": 11,
    "as": "1-ff00:0:120"
}
"""
offline_120_enc = b64url(offline_120.encode('utf-8'))

############################################
# Payload serialization
############################################

payload = b64url(json.dumps(trc_payload).encode())

############################################
# Issuing TRC signatures
############################################

signed_trc = {
    "payload": payload,
    "signatures": [
        {
            "protected": offline_110_enc,
            "signature": sign(off_key_110, (offline_110_enc + '.' + payload))
        },
        {
            "protected": online_110_enc,
            "signature": sign(online_key_110, (online_110_enc + '.' + payload))
        },
        {
            "protected": offline_120,
            "signature": sign(off_key_120, (online_120_enc + '.' + payload))
        },
    ]
}

############################################
# TRC serialization
############################################
# This serialized TRC is the final form that can be
# verified and added to the trust store by each relying party.

serialized_trc = json.dumps(signed_trc)
# {
#   "payload": payload,
#   "signatures": [
#     {
#       "protected": "CnsKICAgICJhbGciOiAiRWQyNT...",
#       "signature": "iCI6IFsiVHlwZSIsIpbmUiCiAg..."
#     },
#     {
#       "protected": "CnsKICAgICJhbGciOiAiRWQyNT...",
#       "signature": "JUeXBlIjogIk9mZmxpbmUiCiAg..."
#     },
#     {
#       "protected": "CnsKICAgICJhbGciOiAiRWQyNT...",
#       "signature": "S2V5VmVyc2lvbiI6IDEciOiyFG..."
#     },
#   ]
# }
````

### Chain Serialization Example

In the following, the serialization of a certificate chain is described.

````py

def b64url(input: bytes) -> str:
    return base64.urlsafe_b64encode(input).decode().strip('=')

############################################
# AS certificate metadata/payload serialization
############################################

as_cert_meta = """
{
    "alg": "Ed25519",
    "crit": ["type", "certificate_version", "isd_as"]
    "type": "certificate"
    "certificate_version": 6,
    "isd_as": "1-ff00:0:130"
}
"""
as_cert_meta_enc = b64url(as_cert_meta.encode('utf-8'))

payload = b64url(json.dumps(as_cert_payload).encode())

############################################
# Issuing AS certificate signature
############################################

signed_as_cert = {
    "payload": payload,
    "protected": as_cert_meta_enc,
    "signature": sign(iss_key, (as_cert_meta_enc + '.' + payload))
}

############################################
# Issuer certificate metadata/payload serialization
############################################

iss_cert_meta = """
{
    "alg": "Ed25519",
    "crit": ["type", "trc_version"]
    "type": "trc"
    "trc_version": 2,
}
"""
iss_cert_meta_enc = b64url(iss_cert_meta.encode('utf-8'))

payload = b64url(json.dumps(iss_cert_payload).encode())

############################################
# Issuing Issuer certificate signature
############################################

signed_iss_cert = {
    "payload": payload,
    "protected": iss_cert_meta_enc,
    "signature": sign(online_key, (iss_cert_meta_enc + '.' + payload))
}

############################################
# Certificate Chain serialization
############################################

chain = [signed_iss_cert, signed_as_cert]

serialized_chain = json.dumps(chain)
# [
#   {
#     "signature": "SIsICJDZXJ0aWZpY2F0ZVZl2F0ZVJpdCI6IFsiVHlwZS...",
#     "protected": "CnsKICAgICJhbGciOiAiRWQyNTUxOSIsCiAgICAiY3Jp...",
#     "payload": "eyJDZXJ0aWZpY2F0ZVR5cGUiOiAiSXNzdWVyIiwgIkNlcn..."
#   },
#   {
#     "signature": "CnsKICAiAgICIjogIlRIl0KICAAiRWQyI6IFsiVHlwZS...",
#     "protected": "CnsKICAgICJhbGciOiAiRWQyNTUxOSIsCiAgICAiY3Jp...",
#     "payload": "eyJDZXJ0aWZpY2F0ZVZlcnNpb24iOiAyLCAiQ2VydGlmaW..."
#   }
# ]
````
