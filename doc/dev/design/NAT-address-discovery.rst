*********************
NAT IP/port discovery
*********************

- Author(s): Marc Frei, Jan Luan, Tilmann Zäschke
- Last updated: 2024-11-25
- Status: **WIP**
- Discussion at: :issue:`4517`

Abstract
========
SCION packet headers contain a SRC address to which packets should be returned. This address needs to be
visible/reachable by the first-hop border router, assuming that the path gets simply reversed by the peer.
This address may not be easy to discover if the sender is separated from the receiver by a NAT.

We want to propose a solution that allows SCION endhosts (and endhost libraries) to discover and use
the address that is visible to the first hop border router as the source host address in outbound packets.
The most elegant and most reliable solution appears to be to have the client (the sending endhost)
detect its NATed IP/port by querying the border router for its publicly visible address.

Background
==========
Scenario: A client sends a packet to a server, containing the clients (assumed) address/port as SRC address. The server
receives the packet and uses the SRC address/port as DST in the response packet. Back in the destination AS, the border
router (BR) uses the DST address/port from the response packet to forward it to the client.
If the client is behind a NAT or similar, the DST address/port (originally the SRC address) must be the address/port at
the NAT as seen by the border router.

The problem we are trying to solve is putting the correct SRC address/port into outbound SCION packets.

There are many solutions to deal with NATs. In our case, if we assume that packet headers may (at some point) need
to be signed, we need a solution that allows a client to inject the correct SRC IP and port into a packet.
"Correct" meaning the IP and port that is visible by the first hop border router so that it can return answer packets
from a remote host to the client endhost.

The basic idea is that the client endhost sends a packet to a destination (let's call it "detector") outside of the
NAT and the detector responds to the sender with a packet that contains the IP and port as seen by the detector.
One example of this approach is the `STUN protocol <https://en.wikipedia.org/wiki/STUN>`_.

One complication is that the local AS of the sender may be split into different subnets and that border routers
are not all in the same subnet.
Another complication is that some NATs may change their port mapping if a client endhost connects to a new
remote IP or port or uses a different local port.

Therefore, it is desirable for the detector to be not only in the same AS and same subnet as the BR, but ideally at the
same IP address, listening on the same port.
Similarly, it is desirable for the client to use the same local port when connecting to the detector and for actual data
packets to the border router.

Separately, we need to specify a way how the client endhost can discover the "detector", i.e. its IP address and port.
In case the detector shares and IP and possibly even port (or uses a fixed port) with the border router, this
discovery is straight forward.
If the port is flexible or the detector runs on a different IP then we need to find a different solution, probably
as an extension to the bootstrapping service.

Proposal
========
Proposed change: Extend the border router to detect NATed addresses/ports and report them back to a client endhost.

Ideally the solution would listen on the same port that would also be used for normal traffic forwarding.
Alternatively, it may be feasible (depending on how sensitive the NAT is) to use a different (fixed) port to
accept requests for reporting addresses.

To avoid potential misunderstandings: this proposal only addresses the problem of SCION clients behind NATs. It is not
the goal to also support NAT traversal techniques such as NAT hole punching SCION-based servers and peer-to-peer
scenarios.

The implementation on the protocol level could be done in several ways:

1.  STUN: The BR needs to detect if an incoming packet is a STUN packet, and if it is, respond to the STUN request.

    -  Advantages: STUN is a well known and mature protocol. There are STUN libraries available in many programming languages.
       It should be easy to implement this.

2.  Extend SCMP with a new INFO message

    -  Advantages: One less dependency on an external library and protocol
    -  Disadvantages: More standardization effort?

An implementation with STUN seems like the better solution, since it is an existing, well known protocol.
Creating a new SCMP extension that provides essentially the same functionality as STUN seems redundant
and doesn't provide any obvious advantages apart from the one mentioned above.

Regarding the STUN solution, there are multiple ways to send a STUN message over the wire:

1. STUN/UDP/IP: The standard way of sending STUN packets as proposed in the IETF standard.

   -  Easy to implement. However, the border router must distinguish between STUN packets and SCION packets.
      This may be done using the magic cookie value, which is part of the STUN header.
      The optional ``FINGERPRINT`` attribute of STUN may also be used as an aid for distinguishing.

      -  Part of the magic cookie field overlaps with the SCION ``nexthdr`` field.
         Reserving the value in that part of the magic cookie (33) would make the distinction unambiguous.
         However, this value is assigned by IANA to "Datagram Congestion Control Protocol",
         which might complicate standardization should we want to support this protocol over SCION in the future.
      -  The ``FINGERPRINT`` attribute contains a CRC-32 checksum of the STUN packet, XOR'ed with the value 0x5354554e.
         This attribute can be checked in addition to the basic check using the magic cookie.
   -  Disadvantage: We cannot use SCION's Packet Authenticator Option
      (`SPAO <https://docs.scion.org/en/latest/protocols/authenticator-option.html>`_) for message integrity.
      If we want to have message integrity/authentication, we need to implement it separately.

      -  The STUN standard provides an optional extension for username/password based authentication.
         This authentication method is probably impractical to implement for our use case.
         However, we might be able to "misuse" the ``MESSAGE-INTEGRITY`` STUN attribute of this mechanism,
         which contains an HMAC of the STUN packet, for our own purpose.
         We might be able to use DRKey to provide the shared secrets for computing the HMAC.

2. STUN/SCION/UDP/IP: Carry the STUN packet (without UDP headers) inside a SCION packet.

   -  Cleaner solution. We can assign a SCION ``nexthdr`` value to STUN to unambiguously distinguish STUN packets from
      regular dataplane packets. (This is also how we handle BFD messages.)
   -  Encapsulating STUN inside a SCION packet makes it possible to use SCION's built-in authentication functionality
      (SPAO) for message integrity/authentication.
   -  Conceptually awkward. STUN was designed as a transport layer payload (to be carried over UDP or TCP).
      If SCION is viewed as a layer-3 protocol (same as IP), carrying STUN messages directly over SCION without
      encapsulation in a transport layer header would be as if we carried STUN directly over IP without UDP or TCP.

3. STUN/UDP/SCION/UDP/IP: Carry an entire STUN packet with UDP headers inside a SCION packet.

   -  Difficult for BR to distinguish from normal dataplane packets.
      The BR would need to look inside every UDP over SCION packet.
   -  Conceptually unclear distinction from normal STUN/UDP messages carried over SCION.

Remark on message integrity/authentication:

An attacker may spoof NAT address discovery (e.g. STUN) message replies to fool the client into assuming a wrong NAT'ed src address.
This would cause returning traffic from subsequent communication by the client to be forwarded to the wrong destination.
In the case of STUN, this attack is mitigated by a 96-bit TxID unique to each request.
It is very unlikely that an attacker can guess the correct TxID at random,
and thus send a spoofed STUN reply message that the client actually expects.
However, an on-path attacker may still be able to modify STUN messages in transit (which have the correct TxID) to cause the same issue.
This could be mitigated by some form of message integrity/authentication, as described above.
On the other hand, it is to be noted that an attacker with such far-reaching abilities could also just intercept plain dataplane packets.
Overall, the threat model is similar to the question about whether we need authentication for intra-AS SCMP messages.

Decision
--------
During the open-source contributors meeting on Nov. 19, 2024, it was agreed that the STUN/UDP/IP solution is preferred
due to its simplicity. However, arguments about message integrity/authentication have not yet been discussed at that time.
It remains to be discussed whether these arguments pose enough reason to changed the preferred solution in favor of the
STUN/SCION/UDP/IP variant.

Rationale
=========
The main reasons for integrating the functionality with the BR are:

-  Reliability: The border router is almost guaranteed to see the correct IP/port on the NAT, especially when using the
   same port for NAT detection traffic and routing traffic. All other approaches rely on the leniency of the NAT to use
   the same port even if the NAT detector and border router have different ports or even IPs.
-  Time to rollout: changing the border routers should be much easier and faster than getting NAT vendors to implement
   SCION compatibility or to get rid of NATs completely in home networks.
   A short time until rollout seems important because people are already running into this problem.

Alternatives:

-  The SRC address/port is updated by the border router to reflect what the border router sees as source address.
   Problem:

   -  Complicates cryptographically protecting the header if the header must be modifiable by border routers,
      e.g. for `SPAO <https://docs.scion.org/en/latest/protocols/authenticator-option.html>`_.

-  The SRC address/port is updated by the NAT. This is similar to having the border router update SRC IP/port.

   - Complicates cryptographically protecting the header if the header must be modifiable by NATs.
   - Requires cooperation of NAT suppliers to include and roll out SCION support to all their devices.

-  Use separate STUN servers. This is a possibility, but adds setup complexity and may not work in all cases. Every
   subnet of an AS that has a border router would also need a STUN server. Moreover, if the STUN server uses a different
   IP (or port) than the border router, then the NAT may decide to use a different port mapping,
   i.e. the STUN server may not see the same IP/port tuple on the NAT that the border router sees. Disadvantages:

   -  This approach may be be problematic with sensitive NATs.
   -  We need to somehow standardize the STUN IP/port and/or communicate it to endhosts, e.g. via the topology.json file
      or the bootstrapping service.

-  Extend SCMP with a new ERROR message: "invalid source address for first hop pkt", similar to error 33.
   The router can verify that for first hop packets, the IP src address (and L4 port if applicable) matches the SCION
   src address (and L4 port).
   If not, it returns an error, with the actual source address attached somewhere, unless we decide
   to change the payload so it contains the IP header of the offending packet (and the IP header should contain the
   NATed IP/port).

   -  Advantage: One roundtrip less in case an endhost doesn't sit behind a NAT or similar.
   -  Disadvantages: Conceptually a bit of a hack. Complicated to implement.
      The BR would need to check every outbound packet as part of the fast path.
      The client would need to somehow buffer sent packets in case of errors to resend them with the correct src address.

-  Remove all NATs and use IPv6 instead. This is technically possible but unlikely to happen anytime soon, especially
   because scarcity of IPv4 addresses is not the only reason why NATs are deployed.

Compatibility
=============

Breaking changes
----------------

This change should not break anything.

However, there are some points that may need more discussion:

- Return paths: the proposal requires packets that come from a server to arrive through the same BR that was used for an
  outgoing request. This currently seems to be the default behavior of servers, but it is not a behavior required
  by the current standard.

- Dispatcherless port range: What if the the port mapping at the NAT doesn't result in a L4 port that is within the
  `"dispatched_ports" range <https://docs.scion.org/en/latest/dev/design/router-port-dispatch.html>`_ ?
  The last-hop BR would then choose the fixed end-host data port (default 30041) as the underlay UDP/IP destination port
  and NAT mapping would fail. Contrary to the previous point, this problem would at least be detectable by the endhost
  based on the proposed NAT IP/port discovery mechanism.

- All client libraries (snet/pan, jpan, ...) will have to accept incoming packets where the underlay UDP port does not
  match with the L4 port, i.e., the underlay port could be the local receiver port (rewritten while passing the NAT)
  whereas the L4 port will still be the NATed port.

Transition
----------

- An "old" client without expectation on NAT IP/port discovery support on the router would simply not use this feature.
  No additional problem here.
- A "new" client sending a NAT IP/port discovery request to an "old" border router should simply fail because the router
  should simply drop a packet that it cannot process.
  The client should then time out and report that the external NAT address could not be established. Instead of timing
  out it could also optimistically assume that no NAT is involved. -> TBD

Implementation
==============
Necessary border router and snet library modifications have been coded for three approaches proposed in the *Proposal* section:
STUN/UDP/IP, STUN/SCION/UDP/IP, and SCMP message extension.
It was agreed that a PR would be created for the STUN/UDP/IP variant.
Support in client libraries (PAN, JPAN) will be added subsequently.
