*********************
NAT IP/port discovery
*********************

- Author(s): Marc Frei, Tilmann Zäschke
- Last updated: 2024-07-01
- Status: **WIP**
- Discussion at: :issue:`4517`

Abstract
========
SCION packet headers contain a SRC address to which packets should be returned. This address needs to be
visible/reachable by the first-hop border router, assuming that the path gets simply reversed by the peer.
This address may not be easy to discover if the sender is separated from the receiver by a NAT.

We want to propose a solution that allows SCION endhosts (and endhost libraries) to discover and use
the address that is visible to the first hop border router as the source host address in outbound packets.
The most elegant and most reliable solution appears to be to have
the border router itself detect the NATed IP/port and report it to the client (to the sending endhost).

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
    -  Disadvantages: More standardization effort? How do we solve authentication?

3.  Extend SCMP with a new ERROR message: "invalid source address for first hop pkt", similar to error 33.
    The router can verify that for first hop packets, the IP src address (and L4 port if applicable) matches the SCION
    src address (and L4 port).
    If not, it returns an error. The actual source address would need to be attached somewhere, unless we decide
    to change the payload so it contains the IP header of the offending packet (and the IP header should contain the
    NATed IP/port).

    -  Advantages: One less dependency on an external library and protocol. Also one roundtrip less in case an endhost
       doesn't sit behind a NAT or similar.
    -  Disadvantages: Conceptually a bit of a hack. The BR would need to check every outbound packet as part of the fast
       path. More standardization effort? How do we solve authentication?

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
[A description of the steps in the implementation, which components need to be changed and in which order.]

TBD when decision for one of the proposed implementation variants has been made.
