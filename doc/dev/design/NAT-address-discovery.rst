*******
NAT address discovery
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
the address visible to the border router. The most elegant and most reliable solution appears to be to have the
border router itself detect the NATed IP/port and report it to the sending endhost.

Background
==========
[Introduction of the topic, description of the problem being solved.]
There are many solutions to deal with NATs. In our case, if we assume that packet headers may (at some point) need
to be signed, we need a solution that allows a sender endhost to inject the correct SRC IP into a packet.
"Correct" meaning the address that is visible by the first hop border router so that it can return answer packets
from a remote host to the sender.

The basic idea is that the sender endhost sends a packet to a destination (let's call it "detector") outside of the
NAT and the detector responds to the sender with a packet that contains the IP/port as seen by the detector.
One example of this approach is the `STUN protocol <https://en.wikipedia.org/wiki/STUN>`_.

One complication is that the local AS of the sender may be split into different subnets and that border routers
may be in different subnets.
Another complication is that some NATs may change their external port if a sender endhosts connects to a new
remote IP or port or uses a different local port.

Therefore, it is desirable for the detector not only be in the same AS and same subnet, but ideally on the same server,
listening on the same port.
Similarly, it is desirable for the sender to use the same local port for connection to the detector and for the
actual connection to the border router.

Separately, we need specify a way how the sender endhost can discover the "detector", i.e. its IP address and port.
In case the detector shares and IP and possibly even port (or uses a fixed port) then this discovery is straight
forward.
If the port is flexible or the detector runs on a different IP then we need to find a different solution, probably
as an extension to the discover/bootstrapping service.

Proposal
========
[A precise statement of the proposed change.]
Extend the border router (BR) with functionality to detect and report NATed addresses back to a local sender endhost.

Ideally the solution would listen on the same port that would also be used for normal traffic forwarding.
Alternatively, it may be feasible (depending on how sensitive the NAT is) to use a different (fixed) port to
accept request for reporting addresses.

The implementation on the protocol level could be done in several ways:

1.  STUN: The BR needs to detect if an incoming packet is a STUN packet, and if it is, treat it is such and respond
    to the STUN request.

    - Advantages:
       - STUN is a well known and mature protocol. There are STUN libraries available in many programming languages.
         It should be easy to implement this.
    - **TODO look up how/whether authentication is handled**
2. Extend SCMP with a new INFO message
   - Advantages: One less dependency on an external library and protocol
   - Disadvantages: More implementation effort. More standardization effort? How do we solve authentication?
3. Extend SCMP with a new ERROR message
    -  **TODO Maybe there is already an ADDRESS-mismatch error?**


Rationale
=========
[A discussion of alternate approaches and the trade-offs, advantages, and disadvantages of the specified approach.]

Compatibility
=============
[A discussion of breaking changes and how this change can be deployed.]
There should not be any breaking changes. In the worst case, a sender tries to get its NAT address from an old
BR. This should simply fail if the wrong port is used or if the packet is not recognized by the BR.

The endhost should time out and report that the external NAT address cloud not be established.

**TODO** How can we avoid this failure in cases where there is no NAT? Can we get the BR version or CS version?
If they are outdated then the client can try without NAT resolution which may simply work if there is not
NAT or fail if there is one.

Implementation
==============
[A description of the steps in the implementation, which components need to be changed and in which order.]
