# Dynamically Recreatable Key (DRKey) Infrastructure

This document presents the design for the Dynamically Recreatable Key (DRKey)
infrastructure.

- Author: Benjamin Rothenberger  
- Last updated: 11.07.2018  
- Status: draft

## Overview
The DRKey protocol enables routers and end hosts to derive symmetric
cryptographic keys on-the-fly from a single local secret.

DRKey is used for:

- SCMP  
- OPT  
- Security Extension

## Notation
    |                     bitstring concatenation
    ^                     superscript
    _                     subscript

    PRF_K (X)             pseudorandom function using key K and taking X as an input
    {X}_PK_A              public key encryption using public key of AS A
    {}_PK_A^-1            public key signing using private key of AS A

    A                     autonomous system
    H_A                   end host identified by their IP address
    CS_A                  certificate server located in AS A

    SV_A                  AS A's local secret value
    K_{A→B}               symmetric key between AS A and AS B
    K_{A:H_A→B:H_B}^{p}   symmetric key between host H_A in AS A and host H_B in AS B for protocol 'p'


## Design
In the DRKey protocol, key establishment is offloaded to the certificate server
(CS). Each certificate server selects a local secret value, which is only shared
with trustworthy entities in the same AS, it is never shared outside the AS. The
secret value will serve as the root of a symmetric key hierarchy, where keys of
a level are derived from keys of the preceding level using an efficient
Pseudo-Random Function (PRF). Thanks to the one-way property of the PRF
function, the derived key can be shared with another entity without disclosing
the higher level symmetric key.

### Key Hierarchy
#### 0th-level
On the zeroth level of the hierarchy, each AS A randomly generates a local
secret symmetric and AS-specific secret value key SV\_A. The secret value
represents the per-AS basis of the hierarchy and is renewed frequently.
#### 1st-level
Given the AS-specific secret value, an AS can derive pairwise symmetric keys
destined for other ASes from this secret value. These derived keys form the
first level of the key hierarchy and are called first-level keys. For example, a
first-level key that is used between AS A and AS B, is derived as follows:

     K_{A→B} = PRF_{SV_A} (B)  

where SV\_A is the AS-specific secret value from the zeroth level of the key
hierarchy.
#### 2nd-level
Using the symmetric keys of the first level of the hierarchy, second-level keys
are derived to provide symmetric keys to hosts within the same AS. Second-level
keys can be established between a pair of AS infrastructure nodes (such as
border routers or servers), end hosts or a combination of both. For example, a
key between end hosts H\_A in AS A and H\_B in AS B is derived as follows:

    K_{A:H_A→B:H_B}^{prot} = PRF_K_{A→B} (“prot” | H_A | H_B)

where “prot” denotes an arbitrary protocol, and H\_A and H\_B represent host
addresses. We distinguish between IPv4, IPv6 and service addresses. For other
second-level keys (e.g., between an AS infrastructure node and an end host), the
derivation process is adapted by including an ISD-AS identifier.

### Key Establishment
#### First Level Key Exchange
The certificate servers are not only responsible for first-level key
establishment, they also derive second-level keys and provide them to hosts
within the same AS. To exchange a first-level key the certificate servers of
corresponding ASes perform the key exchange protocol. The key exchange is
initialized by CS\_B by sending the following request:

    token = A | val_time | timestamp  
    CS_B → CS A : A | B | token | {token}_PK_B^−1

where 'val\_time' specifies a point in time at which the requested key is valid.
The requested key may not be valid at the time of request, either because it
already expired or because it will become valid in the future. For example,
prefetching future keys allows for seamless transition to the new key.  
To obtain valid AS-level certificates to sign and encrypt the first level key
exchange, we can use the SCION control-plane PKI. The request token is signed
with B’s private key to prove authenticity of the request Upon receiving the
initial request, CS\_A checks the signature and timestamp for authenticity and
expiration. If the request has not yet expired, the certificate server CS\_A
will reply with an encrypted and signed first-level key derived from the local
secret value SV\_A.

    K_{A→B} = PRF_{SV_A} (B)  
    ciphertext = {A | K_{A→B}}_PK_B  
    signature = {ciphertext | exp_time | timestamp}_PK_A^−1  
    CS_A → CS_B : ciphertext | exp_time | timestamp | signature

Once the requesting certificate server CS\_B has received the key, it shares it
among other local certificate servers to ensure a consistent view. Each
certificate server can now respond to queries by entities within the same AS
requesting second-level keys.  
All first-level keys for other ASes are prefetched such that second-level keys
can be derived without delay. However, on-demand key exchange between ASes is
also possible. For example, in case a certificate server is missing a
first-level key that is required for the derivation of a second-level key, the
certificate server initiates a first level key exchange.

#### Second Level Key Exchange
End hosts request a second-level key from their local certificate server with
the following request format:

    {type, requestID, protocol, source, destination, optional)}

An end host H\_A in AS A uses this format for issuing the following request to
its local certificate server CS\_A:

    H_A → CS_A : format | val_time | timestamp

Similar to the first-level key exchange, 'val\_time' specifies a point in time at
which the requested key is valid.
The certificate server only replies with a key to requests with a valid
timestamp, and if the querying host is authorized to use the key. An authorized
host must either be an end point of the communication that is authenticated
using the second-level key, or authorized separately by the AS.  
The following second level requests exist:  

    1. AS → AS:
    Key Derivation: K_{A→B}^prot = PRF_{A→B}(“prot”)
    Request: { 0, req.ID, prot, A, B, ⊥ }

    2. AS → end host
    Key Derivation: K_{A→B:H_B}^prot = PRF_{A→B} (“prot” | H_B )
    Request: { 1, req.ID, prot, A, H_B , ⊥ }

    3. end host → end host:
    Key Derivation: K_{A:H_A→B:H_B}^prot = PRF_{A→B} (“prot” | H_A | H_B )
    Request: { 2, req.ID, prot, H_A , H_B , ⊥ }

    4. broadcast:
    Key Derivation: K_{A→B:H_B,C:H_C}^prot = PRF_{A→B,C} (“prot” | H_B | H_C )
    Request: { 3, req.ID, prot, A, H_B , H_C }

### Key Expiration
Secret values must be renewed every 24 hours. Thus, also lower level keys must
be renewed. However, in order to avoid race condition, the validity of
second-level keys must be higher than the corresponding refresh period. Thus, we
assume the following key validity periods:

- Secret value: 24 hours
- First-level keys: 24 hours (inherited)
- Second-level keys: 24 + 0.1 hours

If a specific protocol requires shorter key expiration times, this will be
implemented as an extension to the basic protocol. We envision to use the 'misc'
part in the second level key exchange.

### Key Rollover
Shared symmetric keys are short-lived to avoid explicit key revocation. However,
letting all keys expire at the same time would lead to peaks in key requests.
Such peaks can be avoided by spreading out key expiration, which in turn will
lead to spreading out the fetching requests. To this end, we introduce the
following deterministic mapping:

    offset : (A, B) → [0, t)

that uniformly maps the AS identifiers of the source in AS A and the destination
in AS B to a range between 0 and the maximum lifetime t of SV\_A. The offset is
used to determine the validity period of a key by determining the secret value
SV\_A^j that is used to derive K_{A→B} at the current sequence j such that:

    [ start(SV_A^j) + offset(A, B), start(SV_A^j+1) + offset(A, B) )

## Implementation
The implementation of the protocol will consist of the first level key exchange
between CS. The second level key exchange is implemented between sciond and CS.
Additionally, a key store needs to be implemented to cache keys.

As a key derivation function, we will use AES-CMAC as a single block operation
can be performed in less than 100 cycles on a modern CPU.

### First Level Key Exchange
For the first level key exchange between CS, we can use SignedCtrlPld. Thus, the
signature, certificate and TRC version do not need to be part of the protocol.
#### First Level Key Request
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                             isdas                             +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            valTime                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

timestamp, signature, certificate and TRC version are abstracted in the
SignedCtrlPld.

#### First Level Key Response
     0                   1                   2                   3  
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                             isdas                             +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            valTime                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                             cipher                            +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                           certVerSrc                          +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                           certVerDst                          +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

certVerSrc and certVerDst describe the version of the certificate used to
sign and encrypt the message.

### Second Level Key Exchange
#### Second Level Key Request
     0                   1                   2                   3  
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            protocol                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                             reqID                             +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           timestamp                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            reqType                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                             srcIA                             +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                             dstIA                             +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                          addIA (opt)                          +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         srcHost (opt)                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         dstHost (opt)                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         addHost (opt)                         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           misc (opt)                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

#### Second Level Key Response
    0                   1                   2                   3  
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                             reqID                             +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           timestamp                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                                                               +
    |                                                               |
    +                             drkey                             +
    |                                                               |
    +                                                               +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +                            expTime                            +
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           misc (opt)                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

This response will also be transmitted with SignedCtrlPld.

### Key Store
As a key store, we will use sqlite. It is already used on sciond and CS to cache
certificates and TRCs.
