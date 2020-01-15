# Control-Plane PKI Certificate Renewal

SCION control-plane certificates are short-lived in the order of days. The
process of renewing certificates is automated to reduce the operation overhead.
In this document we describe the certificate renewal request, its format,
and verification. Additionally, we discuss a possible request validation policy
of an issuing AS and the obligations of the requester.

## Table of Contents

- [Certificate Renewal Request](#certificate-renewal-request)
    - [Request Info Fields](#request-info-fields)
    - [Example Request Info](#example-request-info)
    - [Request Payload](#request-payload)
    - [Signed Request](#signed-request)
- [Validation Policy](#validation-policy)
- [Certificate Renewal Response](#certificate-renewal-response)
    - [Payload](#payload)
    - [Supported error names](#supported-error-names)
    - [Serialization](#serialization)
- [Requester Obligations](#requester-obligations)
- [Frequency](#frequency)

## Certificate Renewal Request

To encode the certificate renewal request we want a human and machine readable
format with wide adoption. We opt for JSON as it fulfills these requirements.
However, even though there have been attempts to canonicalize JSON, no such
effort has made it into a widely adopted standard. We leverage [RFC 7515 JSON
Web Signature (JWS)](https://tools.ietf.org/html/rfc7515) for signing the
requests and encode it in the JWS JSON Serialization Representation.

The request payload consists of the request information, which contains the
contents of the requested certificate (e.g. subject, public keys etc) and other
meta data, and proof-of-possessions for all signing keys in the requested
certificate.

The full certificate renewal requests consists of the encoded request payload
and the signature of that payload.

For the field definitions in this document, we use the **integer** type to
refer to a whole number that is either 0 or positive. Every occurence has a
bit-length attached, which dictates the range of valid values for that integer.
Implementations MUST be able to parse all integer values in the range, MUST NOT
create messages that contain values outside of the range, and MUST error out
during validation if they encounter a number outside of the range. Implementations
MUST error out when the number is not in integer representation (so floating point
or exponential notations are disallowed).

Type **string** refers to a UTF-8 string, and type **timestamp** contains the
number of seconds since UNIX epoch (as defined in the [CCPKI
Document](https://github.com/scionproto/scion/blob/master/doc/ControlPlanePKI.md)).

### Request Info Fields

- __subject__: string. ISD and AS identifiers of the entity that owns the
  certificate and the corresponding key pair, as
  defined in [ISD-AS numbering specification](https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering).
- __version__: 64-bit integer. Certificate version, starts at 1.
- __format_version__: 8-bit integer. Version of the TRC/certificate format (currently 1).
- __description__: string. Describes the certificate and/or AS.
- __optional_distribution_points__: Array string. Additional certificate
  revocation distribution points formatted as ISD-AS string. They MUST be
  authoritative in their ISD.
- __validity__:  Object that hints desired validity time to the issuer. The
  issuer is allowed to cut the validity time as it sees fit.
    - __not_before__: timestamp. Desired time before which the certificate MUST
      NOT be considered valid. Signature verification using the certificate
      MUST fail if the time of verification is before this timestamp.
    - __not_after__: timestamp. Desired time after which this the certificate
      MUST NOT be considered valid. Signature verification using the certificate
      MUST fail if the time of verification is after this timestamp.
- __keys__: Object that maps key types (`signing`,`revocation`) to
  an object with the following fields:
    - __algorithm__: string. Identifies the algorithm this key is used with.
    - __key__: Base64-encoded string representation of the public key.
    - __key_version__: 64-bit integer.
- __issuer__: string. ISD and AS identifiers of the issuer, as defined in [ISD-AS numbering specification](https://github.com/scionproto/scion/wiki/ISD-and-AS-numbering).
- __request_time__: timestamp. Time of creating the request info.

### Example Request Info

````json
{
    "subject": "1-ff00:0:120",
    "version": 2,
    "format_version": 1,
    "description": "AS certificate",
    "validity": {
        "not_before": 1480927723,
        "not_after": 1512463723
    },
    "keys": {
        "signing": {
            "algorithm": "Ed25519",
            "key": "TqL566mz2H+uslHYoAYBhQeNlyxUq25gsmx38JHK8XA=",
            "key_version": 21
        },
    },
    "issuer": "1-ff00:0:130",
    "request_time": 1480927000
}
````

### Request Payload

Requesters must prove that they hold the private keys for the public keys
embedded in the Request Info; one proof for each key (_signing_, _revocation_)
is required. The proof-of-possessions are signatures of the request info using
the JWS standard and the request payload is serialized using the General JWS
JSON Serialization Syntax [Section 7.2.1 of RFC
7515](https://tools.ietf.org/html/rfc7515#section-7.2.1).

The request payload consists of the following fields:

- __payload__: The BASE64URL-encoded representation of the request info
  described in the [Request Info section](#request-info).
- __signatures__: JSON array of signature objects, building the proof-of-possession.
    - __protected__: The BASE64URL(UTF8(metadata))-encoded metadata of the signature (see below).
    - __signature__: The BASE64URL encoded JWS signature.

The following fields MUST be present in the metadata object:

- __alg__: The signing algorithm to mitigate algorithm substitution attacks
  [Section 10.7 of RFC 7515](https://tools.ietf.org/html/rfc7515#section-10.7).
- __crit__: The following immutable array `["key_type", "key_version"]`.
- __key_type__: The signing key type (`signing` or `revocation`).
- __key_version__: 64-bit integer containing the signing key version.

If any field other than the four above is present in the metadata, implementations MUST error out.

Implementations MUST support the [Ed25519 signing algorithm](https://tools.ietf.org/html/rfc8032).

The signature input is in accordance with the RFC: `ASCII(protected || '.' || payload)`

### Signed Request

Finally, at the outer-most level is the signed request. It consists of the
encoded request payload and a signature using the Flattened JWS JSON
Serialization Syntax [Section 7.2.2 of RFC
7515](https://tools.ietf.org/html/rfc7515#section-7.2.2).

The signed request consists of the following fields:

- __payload__: The BASE64URL-encoded request payload described above.
- __protected__: The BASE64URL(UTF8(metadata))-encoded metadata of the
  signature. It is the same format as in the request payload.
- __signature__: The BASE64URL encoded JWS signature.

The signature input is in accordance with the RFC: `ASCII(protected || '.' || payload)`

## Validation Policy

These are the properties that define the validity of a certificate renewal request:

- The keys object MUST contain a `signing` key.
- Proof-of-possession of the `signing` key MUST be shown by signing the request
  info with the corresponding private key.
- If a `revocation` key is present in the request info, proof-of-possession MUST
  be shown by signing the request info with the corresponding private key.
- The request SHOULD have a recent `request_time`.
- The request MUST be signed by a key that is compatible with the policy of the
  issuing AS.
- The request MUST be compatible with the additional policies defined by the
  issuing AS.
- All integers must be valid as defined in this document (not negative and not
  overflowing defined bit size)
- JWS compliance (correct fields in protected metadata)

The issuing AS can define its own additional policies. We recommend the following
default policy:

- The `request_time` is more recent than 10 seconds.
- The request is signed with a signing key that is authenticated by a currently
  active AS certificate of the subject.
- The subject has a customer relationship with the issuing AS.
- The new `version` must be current latest + 1.

## Certificate Renewal Response

The certificate renewal response is a signed using the Flattened JWS JSON
Serialization Syntax [Section 7.2.2 of RFC
7515](https://tools.ietf.org/html/rfc7515#section-7.2.2)

### Payload

The payload consists of a json object with two fields:

- __chain__: JSON array with the first entry being the serialized and signed
  Issuer certificate and the second entry being the serialized and signed AS
  certificate.
- __error__: Object indicating the error that occurred with the following
  fields:
    - __name__: string. Specified [error name](#supported-error-names).
    - __message__: string. Arbitrary error message.
    - __ctx__: dict (optional). Arbitrary additional context.

In case of successful certificate renewal the payload consists of the
certificate chain containing the renewed AS certificate.

### Supported error names

- `request_malformed`: Request is missing or has invalid fields.
- `invalid_signature`: Signature failed to verify.
- `not_customer`: Subject is not a customer of the issuing AS.
- `exists`: Requested certificate version already exists.
- `request_expired`: The `request_time` timestamp is too old.
- `policy_violation`: The request violates a policy defined by the issuing AS.

### Serialization

- __payload__: The BASE64URL-encoded payload described above, containing either
  a certificate chain or an error object.
- __protected__: The BASE64URL(UTF8(metadata))-encoded metadata of the signature.
- __signature__: The BASE64URL encoded JWS signature.

The following fields must be present in the metadata object and no others must be set:

- __alg__: The signing algorithm to mitigate algorithm substitution attacks
  [Section 10.7 of RFC 7515](https://tools.ietf.org/html/rfc7515#section-10.7).
- __crit__: The following immutable array `["ia", "version"]`.
- __ia__: The ISD-AS identifier of the issuer AS.
- __version__: The certificate chain version that authenticates the signing key
  of the issuer AS.

The signature input is in accordance with the RFC: `ASCII(protected || '.' || payload)`

## Requester Obligations

As per the [SCION Control Plane PKI
specification](ControlPlanePKI.md#certificate-chain-dissemination), the
requester is required to to register the renewed certificate chain with all
authoritative ASes before using it.

## Frequency

AS certificates are [short-lived](ControlPlanePKI.md#table-certificates). Thus,
AS certificates need to be renewed fairly frequently. We recommend that ASes
request certificate renewals one day before expiration.

In order to provide optimal coverage to its customers, we recommend that the
issuer ASes have an issuer certificate ready that covers the maximum AS
certificate validity (under their policy) at all times.

## Data example

### AS Key pairs

This section contains example key material for an AS. For reproducibility
purposes, the example includes private keys. Implementations must take
precautions to keep these secret. All values use Base64 URL-safe encoding (see
[RFC 3548](https://tools.ietf.org/html/rfc3548))

For reproducibility, the Base64 encodings of the multi-line JSONs in these
examples use tabs for indentantion and a newline at the end of the content.

#### Signing (Ed25519)

- Private: `jJ15HZC6ECC5PH5nmXC5JsYoc7FgSUfWGU80jG_Y7Bg=`
- Public:  `WmTLs8BiEdyLVOSLQR2Oopmt0Wz3ZtFd0v8FKCEB14M=`

#### Revocation (Ed25519)

- Private: `nKpYHbaoARsl1aY3Dzr45-19Ake6CD2CeJoa84ZkwWo=`
- Public:  `RUHOtezvoir6DWVCBBZjf3M_4giLbWgE0o3f4oJQu18=`

### Example Request Info

````json
{
    "subject": "1-ff00:0:120",
    "version": 2,
    "format_version": 1,
    "description": "AS certificate",
    "validity": {
        "not_before": 1480927723,
        "not_after": 1512463723
    },
    "keys": {
        "signing": {
            "algorithm": "Ed25519",
            "key": "WmTLs8BiEdyLVOSLQR2Oopmt0Wz3ZtFd0v8FKCEB14M=",
            "key_version": 21
        },
        "revocation": {
            "algorithm": "Ed25519",
            "key": "RUHOtezvoir6DWVCBBZjf3M_4giLbWgE0o3f4oJQu18=",
            "key_version": 29
        }
    },
    "issuer": "1-ff00:0:130",
    "request_time": 1480927000
}
````

### Example Signature Metadata - Proof of Possession for Signing Key

```json
{
    "alg": "Ed25519",
    "crit": ["key_type", "key_version"],
    "key_type": ["signing"],
    "key_version": 21
}
```

### Example Signature Metadata - Proof of Posession for Revocation Key

```json
{
    "alg": "Ed25519",
    "crit": ["key_type", "key_version"],
    "key_type": ["revocation"],
    "key_version": 29
}
```

### Example Request Payload

```json
{
    "payload": "ewoJInN1YmplY3QiOiAiMS1mZjAwOjA6MTIwIiwKCSJ2ZXJzaW9uIjogMiwKCSJmb3JtYXRfdmVyc2lvbiI6IDEsCgkiZGVzY3JpcHRpb24iOiAiQVMgY2VydGlmaWNhdGUiLAoJInZhbGlkaXR5IjogewoJCSJub3RfYmVmb3JlIjogMTQ4MDkyNzcyMywKCQkibm90X2FmdGVyIjogMTUxMjQ2MzcyMwoJfSwKCSJrZXlzIjogewoJCSJzaWduaW5nIjogewoJCQkiYWxnb3JpdGhtIjogIkVkMjU1MTkiLAoJCQkia2V5IjogIldtVExzOEJpRWR5TFZPU0xRUjJPb3BtdDBXejNadEZkMHY4RktDRUIxNE09IiwKCQkJImtleV92ZXJzaW9uIjogMjEKCQl9LAoJCSJyZXZvY2F0aW9uIjogewoJCQkiYWxnb3JpdGhtIjogIkVkMjU1MTkiLAoJCQkia2V5IjogIlJVSE90ZXp2b2lyNkRXVkNCQlpqZjNNXzRnaUxiV2dFMG8zZjRvSlF1MTg9IiwKCQkJImtleV92ZXJzaW9uIjogMjkKCQl9Cgl9LAoJImlzc3VlciI6ICIxLWZmMDA6MDoxMzAiLAoJInJlcXVlc3RfdGltZSI6IDE0ODA5MjcwMDAKfQo=",
    "signatures": [
        {
            "protected": "ewoJImFsZyI6ICJFZDI1NTE5IiwKCSJjcml0IjogWyJrZXlfdHlwZSIsICJrZXlfdmVyc2lvbiJdLAoJImtleV90eXBlIjogWyJzaWduaW5nIl0sCgkia2V5X3ZlcnNpb24iOiAyMQp9Cg==",
            "signature": "OCmYF_W1s8GMYb0hoYaJ4EQBsChVktNwBneJNGSh_LKXqMjT-IMEPH6Z3TDqRpqvsO3jSALxneME1Tp82_vTCQ=="
        },
        {
            "protected": "ewoJImFsZyI6ICJFZDI1NTE5IiwKCSJjcml0IjogWyJrZXlfdHlwZSIsICJrZXlfdmVyc2lvbiJdLAoJImtleV90eXBlIjogWyJyZXZvY2F0aW9uIl0sCgkia2V5X3ZlcnNpb24iOiAyOQp9Cg==",
            "signature": "JvU9Gpy8dHlkjuCvt7phoGNDBPnZHzhRqxGgGTNTKpaHjzc0UaB-mcI4vEJ-I09meqxrP2ciNUyWg-TaxlpyDA=="
        }
    ]
}
```

### Example Old Signing Key

This _signing key_ must be vouched for by a currently valid certificate of the
same AS (if we go with Option 1).

- Private: "O7egXeYMerDGfczXoUMqKA-qc0E6Xk4T8zZAEtP_HbI="
- Public: "8bPVYzGOkcOG22Qgn_6WEel366mu3LihZ-OQ08q8dPs="

### Example Signature Metadata - Top Signature

```json
{
    "alg": "Ed25519",
    "crit": ["key_type", "key_version"],
    "key_type": ["signing"],
    "key_version": 20
}
```

### Example Signed Request Payload

```json
{
    "payload": "ewoJInBheWxvYWQiOiAiZXdvSkluTjFZbXBsWTNRaU9pQWlNUzFtWmpBd09qQTZNVEl3SWl3S0NTSjJaWEp6YVc5dUlqb2dNaXdLQ1NKbWIzSnRZWFJmZG1WeWMybHZiaUk2SURFc0Nna2laR1Z6WTNKcGNIUnBiMjRpT2lBaVFWTWdZMlZ5ZEdsbWFXTmhkR1VpTEFvSkluWmhiR2xrYVhSNUlqb2dld29KQ1NKdWIzUmZZbVZtYjNKbElqb2dNVFE0TURreU56Y3lNeXdLQ1FraWJtOTBYMkZtZEdWeUlqb2dNVFV4TWpRMk16Y3lNd29KZlN3S0NTSnJaWGx6SWpvZ2V3b0pDU0p6YVdkdWFXNW5Jam9nZXdvSkNRa2lZV3huYjNKcGRHaHRJam9nSWtWa01qVTFNVGtpTEFvSkNRa2lhMlY1SWpvZ0lsZHRWRXh6T0VKcFJXUjVURlpQVTB4UlVqSlBiM0J0ZERCWGVqTmFkRVprTUhZNFJrdERSVUl4TkUwOUlpd0tDUWtKSW10bGVWOTJaWEp6YVc5dUlqb2dNakVLQ1FsOUxBb0pDU0p5WlhadlkyRjBhVzl1SWpvZ2V3b0pDUWtpWVd4bmIzSnBkR2h0SWpvZ0lrVmtNalUxTVRraUxBb0pDUWtpYTJWNUlqb2dJbEpWU0U5MFpYcDJiMmx5TmtSWFZrTkNRbHBxWmpOTlh6Um5hVXhpVjJkRk1HOHpaalJ2U2xGMU1UZzlJaXdLQ1FrSkltdGxlVjkyWlhKemFXOXVJam9nTWprS0NRbDlDZ2w5TEFvSkltbHpjM1ZsY2lJNklDSXhMV1ptTURBNk1Eb3hNekFpTEFvSkluSmxjWFZsYzNSZmRHbHRaU0k2SURFME9EQTVNamN3TURBS2ZRbz0iLAoJInNpZ25hdHVyZXMiOiBbCgkJewoJCQkicHJvdGVjdGVkIjogImV3b0pJbUZzWnlJNklDSkZaREkxTlRFNUlpd0tDU0pqY21sMElqb2dXeUpyWlhsZmRIbHdaU0lzSUNKclpYbGZkbVZ5YzJsdmJpSmRMQW9KSW10bGVWOTBlWEJsSWpvZ1d5SnphV2R1YVc1bklsMHNDZ2tpYTJWNVgzWmxjbk5wYjI0aU9pQXlNUXA5Q2c9PSIsCgkJCSJzaWduYXR1cmUiOiAiT0NtWUZfVzFzOEdNWWIwaG9ZYUo0RVFCc0NoVmt0TndCbmVKTkdTaF9MS1hxTWpULUlNRVBINlozVERxUnBxdnNPM2pTQUx4bmVNRTFUcDgyX3ZUQ1E9PSIKCQl9LAoJCXsKCQkJInByb3RlY3RlZCI6ICJld29KSW1Gc1p5STZJQ0pGWkRJMU5URTVJaXdLQ1NKamNtbDBJam9nV3lKclpYbGZkSGx3WlNJc0lDSnJaWGxmZG1WeWMybHZiaUpkTEFvSkltdGxlVjkwZVhCbElqb2dXeUp5WlhadlkyRjBhVzl1SWwwc0Nna2lhMlY1WDNabGNuTnBiMjRpT2lBeU9RcDlDZz09IiwKCQkJInNpZ25hdHVyZSI6ICJKdlU5R3B5OGRIbGtqdUN2dDdwaG9HTkRCUG5aSHpoUnF4R2dHVE5US3BhSGp6YzBVYUItbWNJNHZFSi1JMDltZXF4clAyY2lOVXlXZy1UYXhscHlEQT09IgoJCX0KCV0KfQo=",
    "protected": "ewoJImFsZyI6ICJFZDI1NTE5IiwKCSJjcml0IjogWyJrZXlfdHlwZSIsICJrZXlfdmVyc2lvbiJdLAoJImtleV90eXBlIjogWyJzaWduaW5nIl0sCgkia2V5X3ZlcnNpb24iOiAyMAp9Cg==",
    "signature": "iPdGUSjCqOBF83JSv8Nk35wbzkacPDdVdLDDgyCw8dY6l1jxgh4fil6RBkn0B1Fbj5ijkc7lL58x428oZufTDA==",
}
```

TODO: Reply example
