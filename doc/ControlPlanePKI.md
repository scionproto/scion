# SCION's Control-Plane PKI

The control-plane PKI (CP-PKI) allows each isolation domain (ISD) to define its own roots of trust
for routing-related decisions. Each ISD maintains its own trust root configuration (TRC), where the
principal ASes of the ISD are specified along with public keys and policies for updating the TRC.
Each version of the TRC must be signed by a number of ASes with voting power in the ISD, so that
updates can be authenticated and validated against previous versions. The TRC can be seen as a
multi-self-signed root certificate.

This document largely borrows from previous design documents and the SCION book, but also proposes
new concepts and simplifies some existing mechanisms.

## Glossary

- __Grace period:__ number of seconds during which the previous version of a TRC is still considered
  active after a new version has been published.
- __Trust anchor:__ certificate, public key, or set thereof that is considered valid axiomatically
  (unless expired or revoked). In other words, a cryptographic object for which trust is assumed
  rather than derived. In SCION, trust anchors are TRCs with a grace period of 0.
- __Trust store:__ list of all trust anchors established and maintained by verifiers.
- __Trust reset:__ action of creating and announcing a new trust anchor for an existing ISD.
- __TRC chain verification:__ process of verifying a series of TRCs with consecutive version numbers
  and the same ISD identifier, starting from a trust anchor.

### TRC Qualifiers

Below are the different states in which a TRC can be (in increasing level of "trustworthiness"):

1. __Verified:__ a TRC whose format and contents are correct and consistent with previous versions.
   The verification of a TRC includes basic sanity checks as well as a TRC chain verification.
2. __Valid:__ a *verified* TRC whose "validity" period (defined in the TRC itself) has begun and has
    not yet ended.
3. __Active:__ a *valid* TRC that may still be used for verifying certificate signatures, i.e.,
   either the latest TRC or the previous one if it is still in its grace period. No more than two
   TRCs can be active at the same time for each ISD.
4. __Latest:__ the TRC with the highest version number. The latest TRC should always be *valid* (and
   thus *active*, by definition).

Other qualifiers for TRCs include the following:

- __Fresh:__ a TRC with a version of 1 (version 0 being reserved to request the latest TRC).
- __Inconsistent:__ different TRCs with the same version number and the same ISD identifier.
- __Expired:__ a TRC whose validity period has ended, or that has been replaced by an update whose
    grace period renders the previous TRC inactive.

## Principal ASes

An ISD is made up of a number of ASes. There is an (open) set of attributes that each AS may have:

- `Core`: AS that has core links to other core ASes.
- `Voting`: AS that participates in and signs TRC updates. It is authoritative for TRCs/certificates
  for the local ISD.
- `Issuing`: AS that issues AS certificates to other ASes in the ISD.

__Principal AS:__ has at least one of the above attributes.

An AS that has no core links is not a core AS. A voting AS must be a core AS (this ensures that it's
reachable by other core ASes for bootstrap purposes), but an issuer AS doesn't have such a
requirement. Voting ASes are required to have both offline and online keys. Non-voting ASes cannot
have offline keys.

All ASes with one or more attributes are considered principal ASes, and are listed in the TRC, along
with their relevant keys.

## Design Goals

During normal operations, the CP-PKI should require minimal human intervention, and updating a TRC
should not interrupt network operation. Conversely, after a severe key compromise human involvement
is desired and even required in some circumstances (which can be enforced by using special
cryptographic keys stored in secure offline locations).

### Authenticity

It should be possible to determine whether fresh TRCs and updates are authentic. More sensitive
actions in the CP-PKI should have higher authentication requirements, i.e., in terms of key type
(offline vs. online) and number of entities involved.

### Resilience

The CP-PKI should be able to tolerate the compromise of a small number of keys and enable recovery
with minimal effort, i.e., without requiring a complete re-establishment of the trust roots of the
corresponding ISD.

It should also be possible for an ISD to recover (with more effort) after some or all of its voting
ASes have been compromised. Otherwise, a badly compromised ISD would have to get a new ISD number,
renumber its entire ISD, invalidate all remote references to the old ISD number, and the old number
would be considered poisoned, forever.

### Isolation

The consequences of a key compromise or TRC update in a given ISD should be strictly limited to
communications with or within that ISD. Compromising any number of ASes in an ISD shouldn't allow
forging TRCs for other ISDs.

### Uniqueness

A TRC must never change after it has been issued. Moreover, there should not exist multiple valid
TRCs with different contents for the same ISD and with the same version number; this kind of
behavior is considered malicious (commonly referred to as a "split-world attack" or "equivocation").
Also, it is not possible to add multiple TRCs with the same ISD identifier to a trust store, unless
a TRC chain verification has succeeded.

### Avoiding circular dependencies (between verification and communication)

Some PKI designs assume that entities can communicate freely with each other. This is not the case
with SCION, as it defines the very communication infrastructure upon which participants rely.
Therefore, one of the main challenges is to avoid circular dependencies, where a communication path
is necessary to establish authenticity and authenticity must be verified to establish a
communication path.

## Trust Model

In this document, "trust" must be interpreted as follows. A set of trust anchors is defined in each
node's trust store. Signatures that can be verified using trust anchors or using public keys
certified by trust anchors must be considered valid, unless a restriction (such as expiration or
revocation) applies. Trust anchors often take the form of self-signed root certificates (also called
roots of trust). In the context of SCION the trust anchors are TRCs.

The two predominant trust models in today's Internet are monopolistic (single root of trust) and
oligopolistic (multiple roots of trust). Typically, in both models, all or some certification
authorities are omnipotent. That is, if their key is compromised, then the security of the entire
system collapses. Moreover, roots of trust are typically defined through independent self-signed
certificates. The SCION trust model is different in mainly two ways. First, no entity is omnipotent;
following the "isolation" design goal, the capabilities of ISDs (authentication-wise) are limited to
communication channels in which they are involved. Second, the trust roots of each ISD are
co-located in a single file, the TRC, which is co-signed by voting ASes of the ISD. The trust store
of each verifier hence consists of a list of TRCs.

## Beacon Format (AS Entry) Modification

This document proposes the addition of the following fields to beacons (in AS entries,
specifically):

- Hash algorithm
- TRC hash

ASes must treat these new fields as follows. When creating an AS entry, the hash of the latest TRC
and the algorithm used to compute that hash must be put into the AS entry. When receiving a beacon,
all AS entries must be verified; this includes verifying the TRC hashes, as follows (in pseudocode):

    verifyBeaconHashes(beacon):
        for each ASEntry in beacon:
            TRC = getVerifiedTRC(ASEntry.ISD, ASEntry.TRCVersion)
            if ASEntry.TRCHash != hash(TRC, ASentry.hashAlgo)
                return false
        return true

If the above verification returns `false`, then the beacon is dropped. The `getVerifiedTRC` function
is defined below. Note that it can return `nil` (in which case the verification fails).

Although this mechanism in itself does not guarantee uniqueness, it helps detecting inconsistent
TRCs with little overhead.

## TRC Format

The TRC is represented as a canonical JSON file. There are a few (logical) groups of data in it,
explained in the following sections. All integers are unsigned and formatted as decimal unless
otherwise specified.

Note that aspects relating to the end-entity and naming PKIs are ignored for the time being. They
may be introduced in a future version of the TRC format.

### Top-Level TRC Fields

This comprises all non-object values in the top level of the TRC.

- `ISD`: 16-bit integer. Unique and immutable ISD identifier.
- `TRCVersion`: 64-bit integer. TRC version, starts at 1. All TRC updates must increment this by
  exactly 1 (i.e., no gaps, no repeats).
- `BaseVersion`: 64-bit integer. Version of the last trust reset TRC.
- `Description`: String. Describes the ISD/TRC in human-readable form (possibly in multiple
  languages).
- `VotingQuorum`: 8-bit integer. Defines how many voting ASes from this ISD need to agree to be able
  to modify the TRC.
- `FormatVersion`: 8-bit integer. Version of the TRC/certificate format (currently 1).
- `GracePeriod`: 32-bit integer. How long, in seconds, the previous unexpired version of the TRC may
  still be considered *active*, i.e., `TRC(i)` is still active until the following time has passed:

  `TRC(i+1).NotBefore + TRC(i+1).GracePeriod`

This formula allows the grace period to be adjusted according to the urgency, i.e., in a key
compromise situation, it may be preferable to have a shorter grace period than during regular
updates. A grace period of 0 is a special case that designates a trust reset.

- `RefreshPeriod`: 32-bit integer. Indicates for how long, at most, in seconds, the TRC may be
  cached before requesting an update.
- `TrustResetAllowed`: Boolean. Specifies whether a third party can announce a trust reset for this
  ISD.

### TRC Section: `Validity`

The following fields must be used to determine whether a TRC is *valid* (not to be confused with
*active*). Timestamps are unsigned 32-bit decimal integers, in seconds since the Unix epoch.

- `NotBefore`: Time before which this TRC cannot be considered *valid*.
- `NotAfter`: Time after which this TRC will no longer be considered *valid*.

### TRC Section: `PrincipalASes`

This is an object that maps principal AS identifiers to their attributes and keys:

- `Attributes`: Set of AS attributes. Can be `Issuing`, `Voting`, and/or `Core`. The set of
  attributes cannot be empty as the AS would not be considered a "principal AS".

- `Keys`: Object that maps key types (strings such as `Online` or `Offline`) to an object with the
  following fields:
  - `KeyVersion`: 64-bit integer. Starts at 1, incremented every time this key is replaced.
  - `Algorithm`: String. Identifies the algorithm this key is used with.
  - `Key`: Base64-encoded string representation of the public key.

### TRC Section: `Signatures`

This is an object that maps AS identifiers to an array of signature objects, which must contain the
following:

- `Type`: String. The type of key used (`Online` or `Offline`).
- `KeyVersion`: 64-bit integer. The version of the key used.
- `Signature`: Base64-encoded string representation of the signature. The signature must be computed
  over the entire TRC, including the `Signatures` section where only the `Signature` fields have
  been removed. This prevents an attacker from simply changing the set of signatures of a TRC to
  come up with another valid TRC for the same ISD and with the same version number (compromising
  "uniqueness") without consent from a voting quorum.

### Example of TRC

    {
        "ISD": 1,
        "TRCVersion": 23,
        "BaseVersion": 1,
        "Description": "Example ISD",
        "VotingQuorum": 2,
        "FormatVersion": 1,
        "GracePeriod": 18000,
        "RefreshPeriod": 1800,
        "TrustResetAllowed": true,
        "Validity": {
            "NotBefore": 1510146554,
            "NotAfter": 1541682554
        },
        "PrincipalASes": {
            "ff00:0:110": {
                "Attributes": ["Issuing", "Voting", "Core"],
                "Keys": {
                    "Offline": {
                        "KeyVersion": 34,
                        "Algorithm": "ed25519",
                        "Key": "K3WE17Q9s/84djid00RREne6SJPQC7gpYS..."
                    },
                    "Online": {
                        "KeyVersion": 22,
                        "Algorithm": "ed25519",
                        "Key": "JvgaODTGiO84O3XdoU4nAFUQO43uTPfDcN..."
                    }
                }
            },
            "ff00:0:120": {
                "Attributes": ["Voting", "Core"],
                "Keys": {
                    "Offline": {
                        "KeyVersion": 11,
                        "Algorithm": "ed25519",
                        "Key": "+XjIxmREKXId2cu9cNEvqMeVjvfBhFMu66..."
                    },
                    "Online": {
                        "KeyVersion": 1000000,
                        "Algorithm": "ed25519",
                        "Key": "0lIsyTRewuHAhtnj2Gt3hVbnNF2wb+0rS..."
                    }
                }
            },
            "ff00:0:130": {
                "Attributes": ["Core", "Issuing"],
                "Keys": {
                    "Online": {
                        "KeyVersion": 42,
                        "Algorithm": "ed25519",
                        "Key": "o9V50Hja2ajyyJYRcAEjrcYCzty+iZFE2d..."
                    }
                }
            }
        },
        "Signatures": {
            "ff00:0:110": [
                {
                    "Type": "Offline",
                    "KeyVersion": 34,
                    "Signature": "tcU3WkbejJkgajyJYAEjrcYCianHkrmbnJBDGfkgjd..."
                },
                {
                    "Type": "Online",
                    "KeyVersion": 22,
                    "Signature": "NI+KmU/QUi0uSWtcU3Wbw5PG3SpwQ43ngk5oLkgaA9..."
                },
            ],
            "ff00:0:120": [
                {
                    "Type": "Offline",
                    "KeyVersion": 11,
                    "Signature": "BnnxUcaB7VrswHnQNVF4B5oZXHm9unyB2cSB0+rw+F..."
                }
            ]
        }
    }

## AS Certificate Format

Similarly to TRCs, AS certificates are represented as canonical JSON files. All integers are
unsigned and formatted as decimal unless otherwise specified.

### Top-Level Certificate Fields

- `Subject`: String. ISD and AS identifiers of the entity that owns the certificate and the
  corresponding key pair.
- `Issuer`: String. ISD and AS identifiers of the entity that signed the certificate.
- `TRCVersion`: 64-bit integer. Version of the TRC the issuer used when signing the certificate.
- `CertificateVersion`: 64-bit integer. Certificate version, starts at 1.
- `FormatVersion`: 8-bit integer. Version of the TRC/certificate format (currently 1).
- `Description`: String. Describes the certificate/AS.
- `CanIssue`: Boolean. Describes whether the subject is allowed to issue certificates for other
  ASes, i.e., `true` indicates an "issuer certificate" and `false` an "AS certificate".
- `Signature`: Base64-encoded string representation of the issuer's signature over the certificate.
- `SigningKeyVersion`: 64-bit integer. Version of the key used to produce the above signature.
- `CCRLDistributionPoints`: Array (optional). Distribution points of control-plane certificate
  revocation lists (CCRLs).

### AS Certificate Section: `Validity`

The following fields must be used to determine whether a certificate is valid. Timestamps are
unsigned 32-bit decimal integers, in seconds since the Unix epoch.

- `NotBefore`: Time before which this Cert cannot be used to verify signatures.
- `NotAfter`: Time after which this Cert may no longer be used to verify signatures.

### AS Certificate Section: `Keys`

This is an object that maps the type of key (`Encryption`, `Signing`, or `Revocation`) to the
algorithm and the key.

- `Keys`: Object that maps key types (strings such as `Encryption` or `Signing`) to an object with
  the following fields:
  - `Algorithm`: String. Identifies the algorithm this key is used with.
  - `Key`: Base64-encoded string representation of the public key.
  - `KeyVersion`: 64-bit integer. Starts at 1, incremented every time the key is replaced.

### Example of AS Certificate Chain

    [
        {
            "Subject": "1-ff00:0:130",
            "Issuer": "1-ff00:0:130",
            "TRCVersion": 2,
            "CertificateVersion": 6,
            "FormatVersion": 1,
            "Description": "Issuer certificate",
            "CanIssue": true,
            "Validity": {
                "NotBefore": 1442862832,
                "NotAfter": 1582463723
            },
            "Keys": {
                "Signing": {
                    "Algorithm": "ed25519",
                    "Key": "SKx1bhe3mh4Wl3eZ1ZsK1MwZwsSfcwvyn4FSI9yTvDs=",
                    "KeyVersion": 72
                }
            }
            "Signature": "kKzkmxSszVGAHnjPfk8wo/hPSHgBIh8J5nHPXt+aCrnQi1SHeF2...",
            "SigningKeyVersion": 42
        },
        {
            "Subject": "1-ff00:0:120",
            "Issuer": "1-ff00:0:130",
            "TRCVersion": 2,
            "CertificateVersion": 1,
            "FormatVersion": 1,
            "Description": "AS certificate",
            "CanIssue": false,
            "Validity": {
                "NotBefore": 1480927723,
                "NotAfter": 1512463723
            },
            "Keys": {
                "Encryption": {
                    "Algorithm": "curve25519",
                    "Key": "Gfnet1MzpHGb3aUzbZQga+c44H+YNA6QM7b5p00dQkY=",
                    "KeyVersion": 21
                },
                "Signing": {
                    "Algorithm": "ed25519",
                    "Key": "TqL566mz2H+uslHYoAYBhQeNlyxUq25gsmx38JHK8XA=",
                    "KeyVersion": 21
                }
            }
            "Signature": "IdI4DeNqwa5TPkYwIeBDk3xN36O5EJ/837mYyND1JcfwIOumhBK...",
            "SigningKeyVersion": 72
        }
    ]

## Overview of Keys and Certificates

ASes have online and offline key pairs. Offline keys are used for infrequent safety-critical
operations that will require administrator involvement to cross an air gap, while online keys are
used for frequent automated operations that do not require administrator involvement. The renewal of
AS certificates is an example of a fully automated operation that occurs every few days and only
requires online keys.

The tables below give an overview of the different keys and certificates used in the CP-PKI. The TRC
contains the offline and/or online keys of principal ASes and is signed with a quorum of root keys
(online or offline, depending on the context); as such, it can be considered a self-signed root
certificate, except that multiple parties are involved. Online and offline root keys are included in
TRCs while other keys are authenticated via certificates. All ASes (including the principal ASes)
use AS certificates to carry out their regular operations (such as signing beacons). Issuing ASes
hold an additional certificate whose only purpose is to authenticate (other ASes' and their own) AS
certificates.

### Table: Private Keys

| Name             | Notation    | Auth.[^1]  | Validity[^2] | Revocation    | Usage                |
| ---------------- | ----------- | ---------- | ------------ | ------------- | -------------------- |
| Offline root key | `K_offline` | TRC        | 5 years      | TRC update    | Sensitive TRC update |
| Online root key  | `K_online`  | TRC        | 1 year       | TRC update    | Regular TRC update <br> Singing issuer cert. |
| Issuer key       | `K_issuer`  | `C_issuer` | 6 months     | Dedicated[^3] | Signing AS cert.     |
| Encryption key   | `K_enc`     | `C_AS`     | 3 months     | Dedicated[^3] | DRKey                |
| Signing key      | `K_sign`    | `C_AS`     | 3 months     | Dedicated[^3] | Path authentication  |

[^1]: Location of the corresponding (authenticated) public key.  
[^2]: Recommended usage period before key rollover (best practice).  
[^3]: As described in the "AS Certificate Revocation" section below.

### Table: Certificates

| Name               | Notation      | Signed by    | Associated key    | Validity[^4]    |
| ------------------ | ------------- | ------------ | ----------------- | --------------- |
| Issuer certificate | `C_issuer`    | `K_online`   | `K_issuer`        | 1 week          |
| AS certificate     | `C_AS`        | `K_core`     | `K_enc`, `K_sign` | 3 days          |

[^4]: Recommended validity period (best practice).

## Establishing and Modifying Trust Anchors

All nodes must be pre-loaded with at least the TRC of their own ISD, and they must be able to obtain
other trust anchors in an authenticated fashion. Initially, trust anchors are all fresh (i.e.,
version 1) TRCs. A fresh TRC must respect the following conditions to be added to a trust store:

- No TRC with the same `ISD` identifier must be in the trust store.
- The `TRCVersion` field must be equal to 1.
- The `NotAfter` validity field must be greater than the `NotBefore` field.
- The TRC must be signed by all keys listed in it.
- All principal ASes with the `Voting` attribute must also have the `Core` attribute.
- Voting ASes must have both offline and online keys.

A numbering authority will coordinate the attribution of identifiers to ISDs globally. It is likely,
however, that this authority will delegate and allocate ISD ranges to regional authorities, which
will then assign specific identifiers to ISDs in their region. These regional authorities must thus
also act as "trust-anchor providers".

Trust-anchor providers must maintain an append-only log of TRCs for their ISD range(s). All ASes
then know there exists a small number of lists they need to fetch. Specifically, certificate servers
regularly contact trust-anchor providers; end hosts and other servers obtain their trust anchors
from certificate servers. This implies that the transmission of trust anchors must be authenticated
by certificate servers.

Even with an append-only log, a split-world attack is still possible: a regional authority could
provide different trust anchors for the same identifier to different clients. For this reason, TRC
hashes must be included into beacons and verified by other ASes, as described above. This
effectively runs a gossip protocol among ASes and allows them to detect inconsistent TRCs.

Aside from fresh TRCs, trust anchors can be re-established with a trust reset. Typically, a trust
reset is needed when at least a quorum of voting ASes' online or offline keys have been compromised,
or when a quorum can no longer be met. A trust reset can only be performed by a trust-anchor
provider, and should only be considered valid if the `TrustResetAllowed` is set to `true`. This
prevents authorities from triggering a "kill switch" on ISDs who decided to set this flag to
`false`.

## Verifying TRC Updates

In this section we describe how TRCs must be verified. This includes a policy check as well as other
basic verifications. Note, however, that a verified TRC is not necessarily valid or active.

For any kind of update, the following conditions must be met:

- The `ISD` identifier field is immutable (i.e., it can never change).
- The `TRCVersion` field must be equal to the previous version + 1.
- The `NotAfter` validity field must be greater than the `NotBefore` field.
- The grace period of the TRC must not be 0. (A TRC with a grace period of 0 indicates a trust
  reset, which is not considered an "update" and discussed later in this document.)
- There must be a number of signatures from voting ASes from the previous TRC greater than or equal
  to the `VotingQuorum` parameter in the previous TRC.
- All voting ASes in the new TRC must sign it either with their online key or offline key (but not
  both, unless both keys are new).
- The TRC must not be signed by non-voting ASes (unless their key(s) is/are new).
- Keys can be updated only with a strictly increasing `KeyVersion` number.

These conditions guarantee that a TRC cannot remain valid if signatures are removed from it or added
to it (which would go against the "uniqueness" design goal).

### Regular TRC Update

A regular update is an update that modifies neither the `PrinicipalASes` section nor the
`VotingQuorum` parameter. It must be created using only online root keys.

### Sensitive TRC Update

A sensitive update is any update that is not "regular" (as defined above). It must be created using
at least a `VotingQuorum` of offline root keys defined in the previous version of the TRC, and the
following conditions must be met:

- Any key that was not present in the previous TRC must sign the new TRC. This guarantees that any
  key present in any version of the TRC has been used to produce at least one signature in the TRC's
  history, which shows a proof of possession (PoP) of the corresponding private key (considered a
  good practice in such a context, see the appendix).
- `VotingQuorum` must be strictly smaller than the number of voting ASes defined in the TRC.
- All principal ASes with the `Voting` attribute must also have the `Core` attribute.
- Voting ASes must have both offline and online keys.

## Fetching TRCs and Certificates

All entities within an ISD must have a recent TRC of their own ISD. On startup, all servers and end
hosts obtain the missing TRCs (if any, from the TRC they possess to the latest TRC) of their own ISD
from a certificate server. TRCs are disseminated to other ISDs via SCION's beaconing process. If the
TRC version number within a received beacon is higher than the locally stored TRC, the beacon server
sends a request to the beacon server that sent the beacon. After a new TRC is accepted, it is
submitted by the beacon server to a local certificate server. Path servers and end hosts learn about
new remote TRCs through the path-segment registration and path lookup processes, respectively.

### Getting a TRC

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

The above code is simplified and does not implement the "version 0 means latest" feature.

### Getting an AS Certificate

    getVerifiedCertificate(isd, as, version, trcVersion):
        cert = trustStoreQueryCertificate(isd, as, version)
        if cert != nil:
            return cert
        trc = getVerifiedTRC(isd, trcVersion)
        cert = downloadCertificate(isd, as, version)
        if verifyCertificate(cert, trc) == true:
            return cert
        return nil

## AS Certificate Revocation

With a validity on the order of days, AS certificates can be considered short-lived. Nevertheless,
an attack window of several days is too large for mission-critical operation. Therefore, the CP-PKI
needs a system for quickly revoking AS and issuer certificates. The revocation status must be
cacheable and efficient to distribute. Also, propagation of revocations must not hinder the
availability of the infrastructure.

The number of ASes in SCION will most likely exceed the number of ASes in the current Internet by a
few orders of magnitude. This, in addition to the short certificate lifetime, will result in a large
number of certificates. However, because certificates are short-lived and because stale revocations
can be discarded, revocation lists will remain small or empty most of the time.

### Suicide Notes

A suicide note attests that a certificate must be revoked and may be signed with the subject's
signing key. However, a `Revocation` key may also be specified in the certificate, in which case the
corresponding private key must be stored offline and used to sign the suicide note instead of the
regular signing key. The revocation key may also be used to request a new certificate from an
issuer, and it may be stored at the issuer (so that the issuer can revoke the certificate in case
the certificate's subject loses the revocation key).

### Control-Plane Certificate Revocation List (CCRL)

Certificates are revoked through a control-plane certificate revocation list (CCRL). The CCRL is a
set of suicide notes, listing the revoked non-expired certificates of an ISD, and has the following
fields:

- `ISD`: The ISD identifier.
- `TRCVersion`: The TRC version to indicate which keys were used during signing.
- `RevokedASCerts`: Dictionary from leaf certificate identifiers to suicide note.
- `RevokedIssuerCerts`: Dictionary from issuer certificate identifiers to suicide note.

## Appendix

### Proof of Possession (PoP)

Evidence that an entity whose public key is known has access to the corresponding private key is
called proof of possession (PoP) of a private key. PoP is important for guaranteeing authenticity
and non-repudiation. For example, suppose Alice has a private key SK and its corresponding public
key PK. Alice has a certificate containing PK. Alice uses SK to sign a transaction T. Without PoP,
Mallory could get a certificate containing the same public key PK. There are two issues: Mallory
could claim to have been the real signer of T, and Alice can falsely deny signing T, claiming that
it was Mallory instead who signed the transaction [RFC 4211].
