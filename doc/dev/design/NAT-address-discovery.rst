*******
NAT IP/port discovery
*******

- Author(s): Marc Frei, Tilmann Zäschke
- Last updated: 2024-05-08
- Discussion at: :issue:`4517`

Abstract
========
SCION packet headers contain a SRC address to which packets should be returned. This address needs to be publicly
visible/reachable by the first-hop border router. This address may not be easy to discover if the sender is separated
from the receiver by a NAT.

We want to propose a solution that allows SCION endhosts (and endhost libraries) to transparently discover and use
the address visible to the first hop border router. The most elegant and most reliable solution appears to be to have
the border router itself detect the NATed IP/port and report it to the client (the sending endhost).

Background
==========
[Introduction of the topic, description of the problem being solved.]

After a client endhost sends a request to a server over SCION, in order to return a packet response to the client,
the border router in the client's AS uses the SRC address from the SCION header and the port of the UDP payload to reach
the client. The SRC address and port are set by the client.
If the client is behind a NAT or similar, the SRC address/port must be the address/port of the NAT as seen by
the border router. The problem we are trying to solve is putting the correct SRC address/port into the SCION packet.

There are many solutions to deal with NATs. In our case, if we assume that packet headers may (at some point) need
to be signed, we need a solution that allows a client to inject the correct SRC IP into a packet.
"Correct" meaning the address + port that is visible by the first hop border router so that it can return answer packets
from a remote host to the sender.

The basic idea is that the client endhost sends a packet to a destination (let's call it "detector") outside of the
NAT and the detector responds to the sender with a packet that contains the IP/port as seen by the detector.
One example of this approach is the `STUN protocol <https://en.wikipedia.org/wiki/STUN>`_.

One complication is that the local AS of the sender may be split into different subnets and that border routers
are not all in the same subnet.
Another complication is that some NATs may change their external port if a client endhosts connects to a new
remote IP or port or uses a different local port.

Therefore, it is desirable for the detector not only be in the same AS and same subnet as the BR, but ideally on the
same server, listening on the same port.
Similarly, it is desirable for the client to use the same local port for connection to the detector and for the
actual data connection to the border router.

Separately, we need specify a way how the client endhost can discover the "detector", i.e. its IP address and port.
In case the detector shares and IP and possibly even port (or uses a fixed port) then this discovery is straight
forward.
If the port is flexible or the detector runs on a different IP then we need to find a different solution, probably
as an extension to the discover/bootstrapping service.

Proposal
========
[A precise statement of the proposed change.]

Proposed change: Extend the border router (BR) to detect NATed addresses/ports and report them back to a client endhost.

Ideally the solution would listen on the same port that would also be used for normal traffic forwarding.
Alternatively, it may be feasible (depending on how sensitive the NAT is) to use a different (fixed) port to
accept request for reporting addresses.

The implementation on the protocol level could be done in several ways:

1.  STUN: The BR needs to detect if an incoming packet is a STUN packet, and if it is, treat it is such and respond
    to the STUN request.

    -  Advantages: STUN is a well known and mature protocol. There are STUN libraries available in many programming languages.
       It should be easy to implement this.

2.  Extend SCMP with a new INFO message

    -  Advantages: One less dependency on an external library and protocol
    -  Disadvantages: More standardization effort? How do we solve authentication?

3.  Extend SCMP with a new ERROR message: "invalid source address for first hop pkt", similar to error 33.
    The router can verify that for first hop packets, the IP src address/port matches the SCION src address/port.
    If not, it returns an error. The actual source address would need to be attached somewhere, unless we decide
    to change the payload so it contains the IP header of the offending packet (and the IP header should contain the
    NATed IP/port).

    -  Advantages: One less dependency on an external library and protocol
    -  Disadvantages: Conceptually a bit of a hack. More standardization effort? How do we solve authentication?


Rationale
=========
[A discussion of alternate approaches and the trade-offs, advantages, and disadvantages of the specified approach.]

The main reasons for integrating the functionality with the BR are:

-  Reliability: The border router is almost guaranteed to see the correct IP/port on the NAT, especially when using the
   same port for STUN traffic and routing traffic. All other approaches rely on the leniency of the NAT to use the same
   port even if the STUN server and border router have different ports or even IPs.
-  Time to rollout: changing the border routers should be much easier and faster than getting router vendors or NAT
   vendors to implement SCION compatibility or to get rid of NATs completely in home networks.
   A short time until rollout seems important because people are already running into this problem.

Alternatives:

-  The SRC address/port is updated by the border router to reflect what the border router sees as source address.
   Problem:
   -  Complicates cryptographically protecting the header if the header must be modifiable by border routers
   -  A spoofed IP causes the border router to route traffic to an unsuspecting target
-  The SRC address/port is updated by the NAT. This is similar to having the border router update tSRC IP/port.
   - Complicates cryptographically protecting the header if the header must be modifiable by border routers
-  Use STUN servers. This is a possibility, but adds setup complexity and may not work in all cases. Every subnet
   of an AS that has a border router must also have a STUN server. Moreover, if the STUN server uses a different IP
   (or port) than the border router, then the NAT may decide to use a different port when connecting to it, i.e. the
   STUN server may not see the same IP/port tuple on the NAT that the border router sees. Disadvantages:

   -  This approach may be be problematic with sensitive NATs.
   -  We need to somehow standardize the STUN IP/port and/or communicate it to endhosts, e.g. via the topo file or
      its successor.
-  Remove all NATs and use IPv6 instead. This is technically possible but unlikely to happen anytime soon.

Compatibility
=============
[A discussion of breaking changes and how this change can be deployed.]

Breaking changes
----------------

This change should not break anything.

Transition
----------

- An "old" client without expectation on STUN support on the router would simply not use this feature. No problem here.
- A "new" client sending a STUN request to an "old" border router should simply fail because the router should simply
  drop a packet that it cannot process.
  The client should then time out and report that the external NAT address cloud not be established.

**TODO** How can we avoid this failure in cases where there is no NAT? Can we get the BR version or CS version?
If they are outdated then the client can try without NAT resolution which may simply work if there is not
NAT or fail if there is one.

Implementation
==============
[A description of the steps in the implementation, which components need to be changed and in which order.]

TODO
