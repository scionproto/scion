# EPIC-SAPV Design

This file introduces EPIC-SAPV and documents its design rationales.

## Introduction

A major threat to network communication are volumetric denial-of-service
(DoS) attacks, where network links or
end hosts are flooded with excessive amounts of traffic. Often such
attacks are only possible when the attacker is able to spoof its
source address. With *source authentication* at network routers,
unauthentic packets can be filtered early, i.e., before they can
reach any bottleneck link or the destination host.

Apart from source authentication, also *path validation* is a
desirable property. Path validation protects the path choices
made by the source of a packet by allowing
the source and destination to verify that every AS on the intended
path has processed the packet. This is particularly important if the
source wants packets to traverse certain ASes because they offer
higher quality of service (e.g., satellite networks, which offer
lower latency) or because they perform important in-network functions
such as filtering. In many cases, paths are selected for compliance
reasons, meaning that packets are not allowed to leave a certain
jurisdiction.

The EPIC (Every Packet Is Checked) protocol [[1]](#1) describes how
those properties can be achieved; EPIC-SAPV is its concrete
implementation for SCION.

While EPIC-HP provides improved path authorization, EPIC-SAPV in
addition enables source authentication at border routers, packet
authentication and path validation at the destination host, and
optional path validation at the source host.

## EPIC-SAPV Overview

In EPIC-SAPV, every packet includes an authenticator calculated by
the source, called hop validation field (HVF), for each AS on the
path. The HVFs are subsequently verified and updated (rewritten) by
the on-path border routers. The updated HVFs serve as proofs to
the end hosts that the packet was indeed forwarded on the intended path.

Packet authentication and path validation for the destination host is
implemented using the SCION Packet Authenticator Option
[(SPAO)](https://scion.docs.anapaya.net/en/latest/protocols/authenticator-option.html).
In order for the source host to also validate the path, the
destination host sends back a response packet containing the updated
HVFs. Path validation for the source host is optional however, and
needs to be explicitly enabled.

The computation of the HVFs and the SPAO authenticator is based on DRKey.

## Procedures

### Control Plane

In the control plane, the ASes do not only append 6 bytes of the hop
authenticators to the beacon, but also the remaining 10 bytes (the
authenticator is the 16 byte long output of a MAC function).
This is the same procedure as in
[EPIC-HP](https://scion.docs.anapaya.net/en/latest/EPIC.html#control-plane).

### Data Plane

The data-plane operations for EPIC-SAPV path type packets are the same
as for SCION path type packets, but the source additionally computes
the per-packet HVFs for every AS on the path (for
which it needs the full 16 bytes of the hop authenticators) plus the
SPAO.
All on-path border routers then validate the HVFs accordingly. In
addition, every egress border router updates (rewrites) its
corresponding HVF with a proof that it processed the
packet. The destination host checks the SPAO, which allows it to
verify the authenticity of the packet (because source and payload are
authenticated), and to validate the path (because also the updated HVFs
are authenticated). If desired by the source, the destination host
sends back a response packet containing the updated HVFs, which allows
the source to also verify the path.
A more concise description can be found in the EPIC-SAPV path
type
[specification](https://scion.docs.anapaya.net/en/latest/protocols/scion-header.html#path-type-epic-sapv).

### Response Packets

Similar to SCION and EPIC-HP path type packets, also EPIC-SAPV
allows to invert the path to enable immediate communication to the
source host. Such reversed EPIC-SAPV packets will however only be
treated as best-effort. Alternatively, an AS can also simply fetch a
new SCION or EPIC-SAPV path for the traffic in the backward direction.

### Registering Path Segments

An AS can register its path segment for the use of EPIC-SAPV, or as
SCION-only. In the first case, the AS registers the segment including
the full 16 bytes of the hop authenticators. In the second case, it
only keeps the first 6 bytes of the hop authenticator, i.e., it
removes the 10 additional bytes. Note that when all hop authenticators
are truncated except for the last two, EPIC-SAPV communication is
not possible, but EPIC-HP still is.

As with EPIC-HP, also EPIC-SAPV traffic can be used for
[hidden-path](https://scion.docs.anapaya.net/en/latest/HiddenPaths.html)
communication: an AS can distribute the authenticators to
a set of trusted sources only, that will be the only ones able
to send EPIC-SAPV traffic over the segment.

Note that an AS cannot publicly register a segment for EPIC-SAPV
(i.e., with the full authenticators) and at the same time distribute
it as a hidden path for EPIC-HP.

### Duplicate Suppression

To protect against replay attacks, EPIC-SAPV assumes that a duplicate
suppression system is deployed at each AS [[2]](#2).

### Traffic Prioritization

To profit from the higher security offered by EPIC-SAPV, it must be
prioritized at the routers over SCION and EPIC-HP traffic; still COLIBRI
packets have a higher priority and some amount of bandwidth must be
reserved for best-effort traffic to support communication without established
DRKeys.
Note that the algorithm calculating the COLIBRI reservation sizes
ensures in the control plane that reservation traffic will never
consume all available bandwidth, while probabilistic monitoring
enforces those decisions in the data plane. Therefore, EPIC-SAPV
communication will not starve because of reservation traffic.

## References

<a id="1">[1]</a>
M. Legner, T. Klenze, M. Wyss, C. Sprenger, A. Perrig. (2020) <br>
EPIC: Every Packet Is Checked in the Data Plane of a Path-Aware Internet <br>
Proceedings of the USENIX Security Symposium
[[Link]](https://netsec.ethz.ch/publications/papers/Legner_Usenix2020_EPIC.pdf)

<a id="2">[2]</a>
T. Lee, C. Pappas, A. Perrig, V. Gligor, and Y. Hu. (2017) <br>
The Case for In-Network Replay Suppression <br>
Proceedings of the ACM Asia Conference on Computer and Communications Security
[[Link]](https://netsec.ethz.ch/publications/papers/replay2017.pdf)
