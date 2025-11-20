# Hummingbird QoS Protocol


- Author: Juan A. Garcia-Pardo
- Last updated: 2025-11-20
- Discussion at: -

## Abstract

Hummingbird is a QoS protocol that runs on top of SCION.
It allows ASes to list part of their bandwidth in marketplaces,
and clients to purchase this bandwidth via reservations.
The protocol consists of three distinct planes:

- Control-plane.
- Marketplace.
- Data-plane.

The control-plane is inherited from the SCION control-plane,
and allows ASes and clients to find paths between source and destination pairs.
Additionally, ASes can create *flyovers* between an ingress and an egress interface,
with certain bandwidth and validity time (start-time and end-time of the flyover).
These flyovers are then listed in a marketplace in the form of *assets*,
and made available for clients to purchase.

At the marketplace, when a client purchases an asset,
it has the right to sell it again, or to convert it into a reservation.
A reservation is created from an asset via a process of *redemption*,
where the client contacts the owning AS with the asset and the client information,
morphing the asset into an intransferrable reservation,
valid only for that particular client.
Reservations are not tradeable anymore, as they work only for the client that redeemed the asset.

Once the reservation is created,
it can be used on a path that transits the owning AS using the ingress-egress pair of the reservation.
If the reservation is used following the specified parameters of bandwidth and validity time,
the packets transiting that AS are guaranteed to be forwarded without losses.

<!-- .. figure:: fig/Hummingbird/one-flyover.png -->
<picture>
<img width="454" height="112" alt="Image" src="https://github.com/user-attachments/assets/0fd03d10-e67a-480a-9af3-404b0dfd1258" />
<figcaption>

    This path between a source end-host in AS A, and a destination end-host in AS D,
    contains only one flyover, guaranteed transit at AS B through interfaces 1🡒2,
    with bandwidth 3Mbps, and valid between 13:20 and 13:40 (full timestamp not shown for brevity).
    Note that the transit through AS C does not have a reservation, thus packets may be dropped there.
</figcaption>
</picture>

The interactions with the marketplace is out of scope of both this document
and the implementation of Hummingbird for SCION in `scionproto`.
This interaction includes the following:

- Publishing assets into the marketplace.
- Purchasing assets from the marketplace.
- Redemption of assets into reservations.


## Control-plane
Once the reservations are obtained by the client,
they can be assembled into existing paths to create a fully or partially reserved path:
fully when all hops contain reservations, partially reserved when not.

Obtaining paths from source to destination is done by means of the SCION control-plane,
and it is typically done by the clients before obtaining the reservations.
Once a regular SCION path exists, and the reservations are obtained,
there is a process of merging both together.
This yields a reserved path, that is usable by the data-plane.


## Data-plane
The data-plane in Hummingbird is organized very similarly to the regular SCION case.
Border routers do not keep state for forwarding other than the token buckets to control the bandwidth usage,
and one secret key.
This key is rotated similarly like the master secret is rotated in the regular SCION case.

The rest of this section is organized as follows:

- Description of the wire format of Hummingbird packets.
- Processing steps of the border router when forwarding a Hummingbird packet.

### Wire Format
A packet using the Hummingbird protocol is similar in structure to a regular SCION one,
and contains the following:

- A path metaheader.
- Between 1 and 3 info fields.
- Between 1 and 52* flyover or hop fields.

*: There is a maximum of 52 flyovers possible on any given path, which comes from the
encoding of the CurrHF. See _CurrHF_ in the Metaheader below for details.

<!-- CurrHF (8 bits) and SegLen[3] ($3 \times 7$bit) limit the amount of flyovers.
A flyover is 5 lines ($5 \times 4 = 20$ bytes).
CurrHF thus can offset up to $2^8/5 = 51$ (52 flyovers). Each SegLen is 7 bit,
can represent up to $2^7 / 5 = 25$ flyovers each, $3 \times 25 = 75$.
The minimum between both CurrHF and SegLen is 52. I will fix this. -->


#### Metaheader

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| C |    CurrHF     |r|   Seg0Len   |   Seg1Len   |   Seg2Len   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          BaseTimeStamp                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  MillisTimestamp  |                  Counter                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **(C)urrINF**: 2-bit index (0-based) pointing to the current info field (see offset calculations below).
- **CurrHF (changed)**: 8-bit index (0-based) pointing to the start of the current hop field
    (see offset calculations below) in 4-byte increments.
    This index is increased by 3 for normal hop fields and by 5 for flyover hop fields,
    which are 12 B and 20 B long, respectively.
    This field can represent $1 + (2^8 / 5) = 52$ flyovers,
    or $1 + (2^8 / 3) = 86$ hop fields (without reservations).
- **r**: Unused and reserved for future use.
- **Seg{0,1,2}Len (changed)**: 7-bit encoding of the length of each segment.
    The value in these fields is the length of the respective segment in bytes divided by 4.
    Seg[i]Len > 0 implies the existence of info field i.
    If a given Seg[i]Len is zero, all subsequent Seg[j]Len with j > i will also be zero.
    Each Seg[i]Len field can represent $2^7/5 = 25$ flyovers,
    or $2^7 / 3 = 42$ hop fields (without reservations).
- **BaseTimestamp (new)**: A unix timestamp (unsigned integer, 1-second granularity, similar to beacon timestamp in normal SCION path segments) that is used as a base to calculate start times for flyovers and the high granularity MillisTimestamp.
- **MillisTimestamp (new)**: Millisecond granularity timestamp, as offset from BaseTimestamp. Used to compute MACs for flyover hops and to check recentness of a packet.
- **Counter (new)**: A counter for each packet that is sent by the source to ensure that the tuple (BaseTimestamp, MillisTimestamp, Counter) is unique. This can then be used for the optional duplicate suppression at an AS.


The number of info fields present in the path is calculated as the amount of
Seg[i]Len that are greater than zero, based on the following:

```go
function InfFieldCount(){
    if Seg2Len != 0:
        return 3
    else if Seg1Len != 0:
        return 2
    else if Seg0Len != 0:
        return 1
    else
        // All fields are zero. Intra-AS path.
        return 0
}
NumInf = InfFieldCount()
```

The path offsets are computed as:

- InfoFieldOffset = 12 B + 8 B · CurrINF
- HopFieldOffset = 12 B + 8 B · NumINF + 4 B · CurrHF


#### InfoField

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|r r r r r r P C|     RSV       |            SegID              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          TimeStamp                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **r**: Unused and reserved for future use.
- **P**: Peering flag. If set to true, then the forwarding path is built as a peering path, which requires special  processing on the data plane.
- **C**: Construction direction flag. If set to true then the hop fields are arranged in the direction they have been constructed during beaconing.
- **RSV**: Unused and reserved for future use.
- **SegID**: Updatable field used in the MAC-chaining mechanism.
- **Timestamp**: Timestamp created by the initiator of the corresponding beacon. The timestamp is expressed in Unix time, and is encoded as an unsigned integer within 4 bytes with 1-second time granularity. It enables validation of the hop field by verification of the expiration time and MAC.


#### Regular HopField

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F r r r r r I E|   ExpTime     |         ConsIngress           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          ConsEgress           |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                        HopFieldMAC                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **F (new)**: Flyover bit. Indicates whether this is a hop field or a flyover hop field. Set to 0 for HopFields.
- **r (unchanged)**: Unused and reserved for future use.
- **I (unchanged)**: ConsIngress Router Alert. If the ConsIngress Router Alert is set, the ingress router (in construction direction) will process the L4 payload in the packet.
- **E (unchanged)**: ConsEgress Router Alert. If the ConsEgress Router Alert is set, the egress router (in construction direction) will process the L4 payload in the packet. ExpTime (unchanged) Expiry time of a hop field. The field is 1-byte long, thus there are 256 different values available to express an expiration time. The expiration time expressed by the value of this field is relative, and an absolute expiration time in seconds is computed in combination with the timestamp field (from the corresponding info field).
- **ConsIngress, ConsEgress (unchanged)**: The 16-bit interface IDs in construction direction.
- **HopFieldMAC (name changed)**: 6-byte MAC to authenticate the hop field. For details on how this MAC is calculated refer to the hop-field MAC computation of the SCION path type.


#### FlyoverHopField

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|F r r r r r I E|   ExpTime     |         ConsIngress           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          ConsEgress           |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                           AggMAC                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  ResID                    |        BW         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        ResStartOffset         |         ResDuration           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
- **F Flyover bit**: Indicates whether this is a hop field or a flyover hop field. Set to 1 for FlyoverHopFields.
- **r, I, E, ExpTime, ConsIngress, ConsEgress**: These values are the same as in the standard HopField. Note that ExpTime is the expiration time of the standard HopField, not the expiration time of the reservation.
- **AggMAC**: See below.
- **ResID**: 22-bit Reservation ID, this allows for approximately 4 million concurrent reservations for a given ingress/egress pair.
- **BW**: 10-bit bandwidth field indicating the reserved bandwidth which allows for 1024 different values. The values could be encoded similarly to floating point numbers (but without negative numbers or fractions), where some bits encode the exponent and some the significant digits. For example, one can use 5 bits for the exponent and 5 bits for the significand and calculate the value as significand if exponent = 0 or (32 + significand) << (exponent - 1) otherwise. This allows values from 0 to almost $2^{36}$ with an even spacing for each interval between powers of 2.
- **ResStartOffset**: The offset between the BaseTimestamp in the Path Meta header and the start of the reservation (in seconds). This allows values up to approximately 18 hours in second granularity.
- **ResDuration**: Duration of the reservation, i.e., the difference between the timestamps of the start and expiration time of the reservation.


### Forwarding Steps for a Hummingbird packet
When a packet arrives at the ingress queue of a border router,
the first step after dequeuing it is to determine its path type.
If the path type is Hummingbird, the border router can determine the following actions:

- Forward it with priority (reserved transit).
- Forward it as best effort.
- Drop the packet.

The following steps are used to determine each action.
During processing, if an inconsistency is found in the packet (declared sizes overflowing the packet, etc.),
the packet is dropped. (left out of the sequence for clarity)

1. If this hop is marked as a flyover:
    1. Compute the FlyoverMAC. The FlyoverMAC is used to further compute the aggregated MAC (AggMAC).
    1. If the reserved flyover is no longer valid, the packet will be best-effort.
    1. The packet is marked internally as guaranteed forwarding.
1. Compute the regular SCION hop field MAC (HopFieldMAC) and compare with that of the packet.
    - Done either from an AggMAC field (if this is a flyover), or directly from the unmodified packet.
    - If the computed MAC is not equal to that of the packet, drop the packet.
1. If the packet was marked as guaranteed forwarding:
    1. Check the bandwidth usage of its reservation. If bucket is full, mark the packet as best-effort.
1. Check the computed guarantee class of the packet:
    1. If it is guaranteed forwarding, forward it with priority.
    1. Otherwise, forward it as best effort.


### Authentication Key ($A_k$) Computation
The first step to compute the flyover MAC is to obtain the authentication key $A_k$.
This is done by creating a 16-byte input buffer (block) and  encrypting it with AES-128,
initialized with the Hummingbird secret value (analogous to the regular SCION master secret).
This input buffer is created as follows:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         ConsIngress           |          ConsEgress           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   ResID                   |        BW         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            ResStart                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         ResDuration           |          0 Padding            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

One block of AES derives the authentication key. Example in Go:
```go
inputBuff := prepareBuffer(in, eg, resID, bw, restStart, resDuration)
block, _ = aes.NewCipher(secretValue)
block.Encrypt(inputBuff, inputBuff)
authenticationKey := inputBuff
```

### FlyoverMAC Computation
Analogous to the authentication key computation, the flyover MAC computation
is done by a block encryption with AES-128,
initialized with the authentication key $A_k$, on a 16-byte input buffer.
The input buffer layout is depicted below:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            DstISD             |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                            DstAS                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            PktLen             |        ResStartOffset         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  MillisTimestamp  |                  Counter                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
Then the FlyoverMAC is computed with one block of AES:

```go
inputBuff := prepareBuffer(dstISD, dstAS, pktLen, restStartOffset, millisTimestamp, counter)
block, _ = aes.NewCipher(authenticationKey)
block.Encrypt(inputBuff, inputBuff)
flyoverMAC := inputBuff
```

### Bandwidth Policing
The bandwidth policing is done by means of a token bucket algorithm,
using 8 bytes to keep a timestamp per reservation ID.
These timestamps can be stored in a global *Timestamps* array,
allowing for an efficient space usage,
provided that the reservation IDs present in the packets are sequential,
which we control.

```go
// Returns true if forwarding with priority.
func BandwidthPolice(pkt, Timestamps) bool
    now := time.Now()
    TS := max(Timestamps[pkt.ResID], now) + (pkt.Len / pkt.BW)
    if TS <= now + BURST_TIME {
        Timestamps[pkt.ResID] = TS
        return true
    }
    return false
```



## Implementation
The implementation requires changes in the border router, namely:
- The border router must support priority queues. Optionally, priority processing of packets.
- There must be a new `Hummingbird` path type, allowing its (de)serialization.

The requirement to support priorities by the border router can be relaxed to only support
priority egress queues, if we assume that forwarding packets at the border router is not bottlenecked
by the processing of the packets.

### Questions
I find two main questions to finish a design to the implementation:

1. A border router with priorities is needed. Will it be enough to add priority queues like proposed on PR #4054 ?
2. The processing of a Hummingbird packet and a SCION one is very similar, but the functions _operate_ on different path types. A decision on how to avoid duplicating code must be made.

### Avoiding code duplication
Generics in Go do not allow the definition of a generic function that uses a generic type as a receiver of
a function, unless the type is constrained to an interface. The following is not allowed:
```go
func processPeer[T any](p *T) (bool, disposition) {
	peer, err := determinePeer(p.PathMeta, p.InfoFields[p.CurrInf])
	if err != nil {
		return peer, errorDiscard("error", err)
	}
	return peer, pForward
}
```
The following IS allowed:
```go
type pathLike interface {
	PathMeta() scion.MetaHdr
	Infofield(int) path.InfoField
	CurrInf() int
}

func processPeer[T any](p pathLike) (bool, disposition) {
	peer, err := determinePeer(p.PathMeta(), p.Infofield(p.CurrInf()))
	if err != nil {
		return peer, errorDiscard("error", err)
	}
	return peer, pForward
}
```

This fact prevents us from simply writing a generic function with the correct _text_ inside
(namely accessing the struct's fields and functions) because the compiler won't allow it:
an interface defining the common behavior of all paths must be defined.

Evenmore, Go does not support template specialization with its generics.
This means that we can't modified a _default_ behavior (e.g. SCION packet processing) with the definition
of a function only for a specialized type (e.g. a Hummingbird path type).
Possibly, the only advantage of using generics here would be easing the task of the compiler to remove
type assertions when using the interface.
The Go compiler has proven to be very efficient in removing this superfluous type assertion code
in the presence of only one type in the call stack, although this would be true only when all functions are
inlined.

With the use of generics we would be forcing the compiler to effectively create distinct definitions
for the distinct path types, which is an assurance that the superfluous type assertion won't be there.

The need to create a common interface to express the processing of all path types is still present though.


### Processing a Packet
The processing of a packet with certain (segment-based) path type looks like this:
```go
// Pseudo-code:
func parsePath() disposition
func validate() disposition // expiry, ingress id, pkt length, transit underlay, src&dst&host.
func verifyMAC() disposition
func updateSegID() disposition
func determinePeer() disposition
func ingressRouterAlert() disposition
func goInbound() disposition // terminal state: local IA delivery.
func doXover() disposition // already present in the path like object?
func validateEgressID() disposition
func egressRouterAlert() disposition
func validateEgressRouterUp() disposition
```
These functions on the packet processor would be written once, dealing with a generic path type.
As an example we can use the `processPeer` function depicted above.

Following this approach, the path types declared a the `slayers` level would either have to support this
`pathLike` interface, or we would create _wrappers_ around them to support the interface.


### Summary
Regarding the implementation, it can be desined as follows:
- The border router will support priority queues.
    A new field `trafficClass` inside the `Packet` struct
can be declared to support priorities.
- The processing of a packet is written in one set of functions:
    the ones we have in `dataplane.go` to process a SCION packet.
    These functions will operate on an interface (aka `PathLike` or similar).
- The path types from `slayers` will be wrapped in a struct each to support the `PathLike` interface,
    or themselves support the `PathLike` interface.
