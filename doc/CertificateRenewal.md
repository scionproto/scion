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

### Request Info Fields

- __subject__: string. ISD and AS identifiers of the entity that owns the
  certificate and the corresponding key pair.
- __version__: 64-bit integer. Certificate version, starts at 1.
- __format_version__: 8-bit integer. Version of the TRC/certificate format (currently 1).
- __description__: UTF-8 string. Describes the certificate and/or AS.
- __optional_distribution_points__: Array string. Additional certificate
  revocation distribution points formatted as ISD-AS string. They must be
  authoritative in their ISD.
- __validity__:  Object that hints desired validity time to the issuer. The
  issuer is allowed to cut the validity time as it sees fit.
    - __not_before__: timestamp. Desired time before which the certificate may
      not be used.
    - __not_after__: timestamp. Desired time after which this the certificate
      may no longer be used to verify signatures.
- __keys__: Object that maps key types (`encryption`, `signing`,`revocation`) to
  an object with the following fields:
    - __algorithm__: string. Identifies the algorithm this key is used with.
    - __key__: Base64-encoded string representation of the public key.
    - __key_version__: 64-bit integer.
- __issuer__: string. ISD and AS identifiers of the issuer.
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
        "encryption": {
            "algorithm": "curve25519",
            "key": "Gfnet1MzpHGb3aUzbZQga+c44H+YNA6QM7b5p00dQkY=",
            "key_version": 21
        },
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

The proof-of-possessions are signatures of the request info using the JWS
standard and the request payload is serialized using the General JWS JSON
Serialization Syntax [Section 7.2.1 of RFC
7515](https://tools.ietf.org/html/rfc7515#section-7.2.1).

The request payload consists of the following fields:

- __payload__: The BASE64URL-encoded request info described above.
- __signatures__: JSON array of signature objects, building the proof-of-possession.
    - __protected__: The BASE64URL(UTF8(metadata))-encoded metadata of the signature.
    - __signature__: The BASE64URL encoded JWS signature.

The following fields must be present in the metadata object and no others must be set:

- __alg__: The signing algorithm to mitigate algorithm substitution attacks
  [Section 10.7 of RFC 7515](https://tools.ietf.org/html/rfc7515#section-10.7).
- __crit__: The following immutable array `["key_type", "key_version"]`.
- __key_type__: The signing key type (`signing` or `revocation`).
- __key_version__: The signing key version.

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

- The keys object MUST contain a `signing` and `encryption` key.
- Proof-of-possession of the `signing` key MUST be shown by signing the request
  info with the corresponding private key.
- If a `revocation` key is present in the request info, proof-of-possession MUST
  be shown by signing the request info with the corresponding private keys.
- The request SHOULD have a recent `request_time`.
- The request MUST be signed by a key that is compatible with the issuing AS's
  policy.
- The request MUST be compatible with the additional policies defined by the
  issuing AS.

The issuing AS can define its own additional polices. We recommend the following
default policy:

### TODO Discuss what policy makes more sense for now

_Option 1:_

The issuing AS does the following additional checks:

- The `request_time` is more recent than 10 seconds.
- The request is signed with a signing key that is authenticated by a currently
  active AS certificate of the subject.
- The subject has a customer relationship with the issuing AS.
- The new version must be current latest + 1.

_Pros:_

- easy to implement (1 additional table with all customers in the DB)
- powerful in the sense that it allows an AS to have multiple sets of keys that
  can be updated individually.

_Cons:_

- Compromise recovery needs additional logic, i.e., there needs a way to disable
  automatic renewal. It can only be activated again after all the compromised
  certificates have expired, or some blacklist/whitelist mechanism for the
  lifetime. In the meantime a new certificate has to be created out-of-band.

_Option 2:_

The issuing AS does the following additional checks:

- The `request_time` is more recent than 10 seconds.
- The reuest is signed with a signing key that is authenticated by the latest AS
  certificate of the subject.
- The subject has a customer relationship with the issuing AS.
- The new version must be current latest + 1.

_Pros:_

- More restrictive, thus easier to recover from key compromise. I.e., the issuer
  simply puts a garbage key into the database until a new certificate has been
  created out-of-band.
- Certificate renewal is still possible, even if the latest certificate chain
  expired.

_Cons:_

- Less powerful, one single key that is allowed to do renewals
- Need to pre-load keys instead of simply specify the customer relationship.
- Updating the newest key becomes more involved.

_Opinion_: I think option 1 is better at this point in time, because it is a lot
easier to implement. While the pro of option 2, that certificate renewal is
still possible is compelling, it can also be achieved with some minor extension
to option 1 at a later stage.

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
    - __name__: string. Specified [error identifier](#supported-errors)
    - __message__: string. Arbitrary error message
    - __ctx__: dict (optional). Arbitrary additional context.

In case of successful certificate renewal the payload consists of the
certificate chain containing the renewed AS certificate.

### Supported error names

- `request_malformed`: Request is missing or has invalid fields.
- `invalid_signature`: Signature failed to verify.
- `not_customer`: Subject is not a customer of the issuing AS.
- `exists`: Requested certificate version already exists.
- `request_expired`: The `request_time` timestamp is to old.
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
AS certificates need to be renew fairly frequently. We suggest that ASes request
certificate renewals one day before expiration.

In order to provide optimal coverage to its customers, we suggest that the
issuer ASes have an issuer certificate ready that covers the maximum AS
certificate validity (under their policy) at all times.

