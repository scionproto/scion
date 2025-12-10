# Hummingbird QoS Protocol


- Author: Juan A. Garcia-Pardo
- Last updated: 2025-12-01
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
morphing the asset into an intransferable reservation,
valid only for that particular client.
Reservations are not tradable anymore, as they work only for the client that redeemed the asset.

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

The wire formats of the Hummingbird headers are available in
[TODO change to file `doc/protocols/hummingbird-headers`]
PR #4849.


## Control-plane
The interactions with the marketplace are out of scope of both this document
and the implementation of Hummingbird for SCION in `scionproto/scion`.
For reference, but not authoritatively, this interaction includes the following:

- Publishing assets to the marketplace.
- Purchasing assets from the marketplace.
- Redemption of assets into reservations.

Once the reservations are obtained by the client,
they can be assembled into existing paths to create a fully or partially reserved path:
fully when all hops contain reservations, partially reserved when not.

Obtaining paths from source to destination is done by means of the SCION control-plane,
and it is typically done by the clients before obtaining the reservations.
Once a regular SCION path exists, and the reservations are obtained,
there is a process of merging both together.
This yields a reserved path, that is usable by the data-plane.


## Border Router
The border router in `scionproto/scion` needs to be modified in order to
forward packets of Hummingbird path type.

The high level steps necessary to forward a Hummingbird packet are:
1. Check the path type.
2. Parse the packet into a Hummingbird path structure.
3. Determine if priority applies (check `Flyover` bit).
    1. If not priority, go to 4. Otherwise, set the priority flag in the processor for this packet.
    2. Check flyover MAC. Drop if incorrect.
    3. Check reservation validity, if outside it, unset the priority flag in the processor.
    4. Recompute SCION MAC and go to 4.
4. Check SCION MAC. Drop if incorrect.
5. Update SegID and CurrHF.
6. Check bandwidth usage. If exceeded, unset the priority flag in the processor for this packet.
7. Move to the forwarding queue *Priority* if the priority flag is set in the processor,
    or to the forwarding queue *Best Effort* otherwise.


### Bandwidth Policing
The bandwidth policing is done with a token bucket algorithm,
using 8 bytes to keep a timestamp per reservation ID.
These timestamps can be stored in a border-router-available *Timestamps* array,
allowing for an efficient space usage,
provided that the reservation IDs present in the packets are sequential
(which we can control when we design the publishing of the assets to the marketplace).
Example in a pseudo-Go function:
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
