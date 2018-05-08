# Revocation Authentication

This document presents the new design for interface revocation authentication. Revocation
authentication was done using hash trees, see chapter 7.3.3 of the book. This is was not practical
and was therefore migrated to use digital signatures.

### Hash Tree based Mechanism

A major complication was that revocation authentication was coupled to the path segment. This made
it very hard for applications to handle revocations correctly, since applications that only have
end-to-end paths couldn't verify a revocation, so they had to rely on sciond, and sciond could only
verify the revocation if it happened to have the corresponding path segment. Furthermore, the
connected hash-trees are complex and difficult to operate.

## Digital Signatures

Similar to the PCBs and path segments, a signature over the revocation message can be created using
the AS's private key. Anyone can then easily verify the revocation using the AS's public key,
contained in the AS's certificate.

### Verifiers

Path servers, beacon servers and end hosts (SCIOND) verify revocations. They can verify the
signature using the revocation issuer AS's certificate. A border router does not verify the
signature when it receives a revocation from its local BS, it only checks if it is valid and then
deactivates the corresponding interface.

Validity window: `[timestamp; timestamp + TTL]`, the TTL has a minimum (and default) of 10sec.

### Flooding Attacks

End hosts, path servers and beacon servers verify the signatures. Therefore steps need to be taken
to avoid signature flooding attacks. Only signatures of revocations which are in the validity window
and contain valid values should be checked. A further measure could rely on lightweight hash trees,
this is postponed.

### Downsides

Digital signatures need more processing power than verifying a hash tree entry. According to a
benchmark in python, signature verification takes roughly 4-5 times as long as verifying a HashTree
entry.

## Infrastructure Changes

### Packet Structure

A revocation message has an IFID, an ISD-AS, a link type, a timestamp, and a TTL. It can be packed
into an SignedBlob as data blob. The SignedBlob contains a signature over the blob. The hashTreeRoot
attribute was removed from the ASEntry struct.

### SCIOND

Upon reception SCIOND checks the revocations validity and tries to verify the signature. Then the
revocation is stored in the cache for its TTL. Then SCIOND loops through PCBs and removes any
affected up, down or core PCB.

### Reception: Beacon and Path Server

Upon reception from the network or zookeeper BS and PS check the revocations validity and try to
verify the signature. Then the revocation is added to the local cache (and sent to zookeeper if not
received from it).

*   A BS removes affected PCBs. And sends the revocation to the local PS.
*   A PS removes all revoked segments by looping over all segments. Further it forwards the
    revocation to other path servers if necessary. This includes forwarding revocations from a local
    PS to the core ASes and from a core PS to other core ASes.

### Creation of Revocaton: Beacon Server

BS can decide on the revocation period (TTL) when creating revocations, the default period is 10
seconds. To reduce issues with timing, a revocation is renewed 2 seconds before it is expired. A
revocation is cached at the BS and sent to the local BRs and PS.

### Path Combinator

The path combinator still needs to check if a peer segment it wants to use is revoked, but it does
not need to validate/verify the revocations anymore.
