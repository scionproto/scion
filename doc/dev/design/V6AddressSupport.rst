*****************************
V6 compatible SCION addresses
*****************************

:Author(s): J-C HUgly
:Last updated: 2023-08-31
:Status: **proposal**
:Discussion: `Discussions/4324`_


.. _`Discussions/4324`: https://github.com/scionproto/scion/discussions/4324

Abstract
========
Among other IPV6 compatibility aspects we've been discussion the possibility of making
SCION addresses a special case of IPV6 address. This requires changes to the specification
of SCION addresses so it can fit in 128 bits. I have made a few informal suggestions during
the discussion. This documents proposes a concrete design for supporting a realistic
subset of those suggestions in real code.

This includes all relevant aspects:

* Validation/Identification:

  * "Is this V6 address a valid SCION address?"
  * "Is this scion address representable as V6?"

* Structured conversions:

  * "Turn this V6 address into a SCION address if you can."
  * "Turn this SCION address into a V6 address if you can."

* String representation:

  * "Construct a SCION address from this V6 address string."
  * "Construct a SCION address from this SCION-style address string if you can."

* Viable migration path and future growth support:

  * Configurable address structure with support for the existing V6-incompatible
    structure.
  * Support of existing addresses that are convertible to the new structure
    (most or all should be).
  * Transcoding capability to/from legacy wire format
    (that's a strech goal - it might not be entirely feasible).

Background
==========

Currently SCION addresses are specified to be as large as as 192 bits. As a result they
are both logically and physically incompatible with IPV6 addresses. Although nothing says
that SCION has to use IPV6 addresses in order to cohabitate peacefully with IPV6, the adoption
of SCION would be greatly facilitated if applications did not need to be modified in order
to take at least some advantage from SCION connectivity. Currently, in order for an application
to make any realisitic use of SCION, it needs new code to at least:

* Parse non-standard textual addresses (from, config files or URLs).
* Use non-standard DNS queries, with non-standard responses, from servers configured
  with unusual, if legal, records.
* Access the SCION network via a dedicated API.

Instead, what we would like is that applications can use SCION without even knowing
it, simply as a result of:

* Parsing a normal-looking textual V6 address from a config file or URL.
* Getting a normal AAAA result from a DNS query.
* Opening a UDP/TCP connection to said address via the regular socket API. This would imply
  the existence of SCION-aware code below the socket API that:

  * Recognizes scion addresses and handles the traffic accordingly.
  * Performs some default route selection on behalf of the oblivious application.

This proposal does not cover the last topic. However resolving the first two is a
necessary condition to resolving the last one, since an unmodified application has the
INET4 or INET6 address family assumption wired in its code.

Nevertheless, this objective implies that SCION addresses be distinguishable from non-SCION,
without any additional hint. This creates another constraint on the present design: a valid
SCION addresses must never be bitwise identical to a non-SCION address. Therefore, SCION
addresses must occupy their own, properly reserved, portion of the IPV6 address space.
Therefore they must not just be IPV6-like addresses, they must **be** IPV6 addresses.

This constraint comes with a silver-lining though. Currently, SCION addresses are very large
because they include a complete IPV6 address as a way to designate the destination host within
the destination AS. If SCION addresses are real IPV6 addresses, there is no need to embbed
the destination host's IPV6 address in its SCION address; they are one and the same. This means
that we "only" need to fit the ISD-AS portion (64 bits) of a SCION address into a V6 address
(128 bits). This may seem like a trivial task; in reality we have to sacrifice some things.

Here are the constraints:

* RFC4291 insists on the 64 LSbits to be available to contain a NIC number.
* RFC6890 Instructs IANA to reserve 2001::/23 for experimental protocols, which they allocate
  in blocks of /29. Many of those are available and probably easy to get.
  (https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml)
* RFC3587 reminds that IANA does not allocate addresses outside the 2000::/3 range
  (https://www.iana.org/assignments/ipv6-unicast-address-assignments/ipv6-unicast-address-assignments.xhtml).
  However it is not forbidden from doing so and there's still plenty of space
  (e.g. 2d00:0000::/8 is not assigned and nothing is after that).

So, we have to fit ISD-AS, currently specified as 64 bits, into anywhere between
36 and 56 bits under realistic conditions. We could conceivably have 61 bits if
IANA could be persuaded to dedicate an entire /3 block to SCION but that's not going
to happen until SCION becomes the dominant internet protocol. So we probably shouldn't
lead with that.

Getting a pair of /29 blocks is likely easy with the following caveats:

* It is meant for experimental protocols, so typically temporary. IANA will want to
  set an end date. If do that we have to plan on moving within a few years.
* It gives us only 36 bits; another reason to plan on moving.

Getting a /8 block is probably feasible, especially if we have an IETF sponsor. That leaves
us 56 bits, which is quite enough unless SCION is successful beyond belief, in which case
it will make sense to ask for a larger block and we'll get it.

If we ever get a /3 block, we'll have to move as the price to get more bits for ISD-AS numbers.
We can't count on getting it today, so we just need to be able to move.

So, it seems like explicitly supporting changes in prefix and address structure is a good
investment that will make it easier for us to move several times.


Proposal
========

Address structure roadmap
-------------------------

* Near-term (1 or 2 years):
  Get a /28 block. Cram ISD-AS into 36 bits.
* Mid-term (~10 years, depending on adoption):
  Get a /8 block. Expand ISD-AS to 56 bits.
* Long-term (if and when SCION becomes huge):
  Get a /3 block. Expand ISD-AS to 61 bits.
* In your wildest dreams:
  IPV6 is deprecated in favor of SCION. ISD-AS expand to 64 bits,
  with the exception of some blocks reserved for legacy V6 and special purpose.

Address structure evolution
---------------------------

* 36 bits ISD-AS:

  * ISD is currently defined as a 16 bits field with only 12 bits
    allowed to be non-zero. The rest is specified as reserved. So, 12 bits ought
    to be enough for as long as we refuse to change the spec.
  * AS is currently defined as a 48 bit field but only the following is
    allowed:

    * One 32 bits-wide block for IP ASNs.
    * One 32 bits-wide block for pure SCION ASNs.
    * One 16 bits-wide block for examples.
    * One 24 bits-wide block for test deployments.
    
    The two different ASNs blocks exist so that IP ASNs can be grand-fathered
    into SCION while non IP ASNs can be given a SCION ASN number without
    coliding with the grand-fathered numbers. However, IP ASNs only use
    19 bits today (https://www.iana.org/assignments/as-numbers/as-numbers.xhtml).
    The rate of allocation is about linear at a rate of ~6K/Y, so it won't
    even double over the next 20 years.

    We need 1 bit to maintain our pure-scion/grandfathered spaces.

    If we don't want to retain our examples and private numbers without complications,
    we add one bit to set aside the space for them.

    That's a total of 21 bits. Add one bit to cover for the growths of the next 20 years:
    that's 22.
  * Therefore, strictly speaking we only **need** 34 bits for the next 20 years. Since
    we have 36 available, we can even be wasteful and throw two extra bit to the
    ISD number. Why the ISD? That's because at 14 bits it is less likely to require
    future expansion. That way, we might avoid having to change it any time soon.
    The AS number, on the other hand, is likely to need future expansion anyway.

* Growing into the bright future; 56-bits ISD-AS:

  * The AS number expands to 42 bits (unless my earlier prediction was wrong
    and we need to grow ISD).
  * If we were smart about the layout and put the AS number on the left side, we can
    grow the field in-place; so increasing the permissible whidth without moving
    anything. Chances are it'll make the migration easier. Of course, if we have
    to change the ISD width too, then we loose that benefit. Oh well.
  * The growth comes with a change of address prefix, so, the code can tell how
    to read and write addresses. If we did our job right, this is entirely contained
    in header and address code that already knows how to do that.

* The same pattern coutinues with a /3 block:

  * For what it's worth, the ASN number can grow to 47 bits (not 48... too bad).

* SCION has taken over the internet:

  * We can finally expand ISD-AS to its glorious initial specification (at the
    expanse of being forced to move the boundary between the two; that's a good
    problem to have, I guess).

Configuration
-------------

The relative ease of performing these transitions is predicated on having code
already in-place to manipulate SCION addresses and the ISD-AS fields in headers
(if/when we use the new representation on the wire) according to the applicable
address structure. This code would need to apply the
bit widths and offsets outlined in the handfull of schemes described in
`Address structure evolution`_. Since battle plans rarely survive the first
encounter with the ennemy, it would be wise to make some details configurable,
especially since some of those are outright unknown, for example the prefixes that
IANA would grant us.

The following scheme is proposed:

A small number of valid address format recipes are specified in the form of
a tuple: (IPV6-prefix, ASN-width, ISD-width, Host-width) where:

* IPV6-prefix:
  A prefix in the form v6-addr-fragment/width, for example "2001:40::/28"
  which indicates that the rest of the parameters describe the encoding of
  a SCION addresses in that block.
* ASN-width:
  The number of bits used to represent ASN.
* ISD-width:
  The number of bits used to represent ISD.
* HOST-width:
  The number of bits used to uniquely identify the destination host within the
  destination ISD-AS.

The existence of one such a recipe indicates that SCION addresses of the
given ASN and ISD widths must be encoded as IPV6 addresses of the given block,
and that IPV6 addresses in that block must be decoded into SCION addresses
according to the given widths. There can be multiple valid recipes, as
explained in the section `Migration between IPV6 representations`_

The existence of multiple applicable formats is necessary to support migration
periods during which two different blocks of V6 addresses are assigned and not
every host has been updated. An additional configuration item describes which
recipe to preferably follow when encoding SCION addresses into V6 addresses.
The preference applies to addresses that *can* be represented according to that
recipe. Since we would only carry out address growth, it should be expected that
all existing addresses can be represented in the new scheme, but out of precaution,
we should be able to perform downgrades too.

These recipes would direct the operations of the following code (non-exhaustive):

* Convert a binary V6 address into a componentized SCION address structure.
* Convert a componentized SCION address into a V6 address structure,
* Validate that a V6 address is convertible to a SCION address (i.e. it is in
  a SCION block).
* Validate that a componentized SCION address is convertible to a V6 address (i.e.
  the bit width are compatible with one of the allowed recipes).
* Shortcut methods to parse SCION addresses from, or print then to, V6 textual
  representations.
* Shortcut methods to parse V6 addresses from, or print then to, SCION textual
  representations.

Migration between IPV6 representations
--------------------------------------

A migration from one address scheme to the next would occur in three phases:

* Phase 1:
  Between 0 and 100% of hosts have received the new recipe config.
  Every host continues encoding SCION addresses according to the old scheme but
  is already able to decode either, which never happens.
* Phase 2:
  100% of hosts have received the new config.
  Between 0 and 100% of hosts have received the new preference config and thus
  encode addresses in the new block with the new scheme.
  All can decode.
* Phase 3:
  100% of hosts use the new scheme.
  Between 0 and 100% of the hosts have received a new config lacking the old scheme.
  It is alredy safe to create addresses that do not fit in the old scheme.

Interrestingly, a SCION address (in its component form) does not need to carry
the IPV6 range to which it belongs because both ranges are valid during transitions
and the only valid one is known by config otherwise. There is one caveat, though.
The destination router must use the one that the destination host is using. This
could cause some difficulties that deserve closer examination.


Rationale
=========

Alternatives considered (regarding hidding SCION-specifcs from apps):

* Do Nothing:

  * SCION can only be used via especially crafted applications or the SCION gateway.
  * The gateway is inherently limitted by the IP-SCION address mapping. If all of SCION
    has to be used through it, then it is pointless.
  * Are we planning on providing replacement for all the applications and libraries
    using internet today? Is someone else?

* Map IPV6 addresses to scion ISD-AS downstream from the application:
  That's only a temporary patch see the same issue with the gateway.

Compatibility
=============

Migration from current addressing
---------------------------------

The address format described in this proposal needs not, at first, apply to the wire fomat.
The main objective is for applications to be able to designate SCION hosts by way of a
regular IPV6 address. This means that the only decoding and encoding taking place must be
at the boundary of the SCION API. An application would be allowed to use new methods that
accept IPV6 addresses in-lieu of SCION addresses, and chose a default route implicitly.

However, the SCION/IPV6 address encoding is predicated on the fact that the the full IPV6
address of the destination host is identical to its SCION address; this means that:

* When the new schema is in use, a destination address supplied by the application
  is partially redundantly encoded as the HOST portion of the wire format SCION address.
* That address is a real IPV6 address, reachable by the destination border router.

Until we reach the point where scion routing is part of the normal network stack (and therefore
scion addresses need to be distinguished from other V6 addresses) we can get away with using
arbitrary IPV6 addresses in the unique local range. After that, we need to start using real
assigned IPV6 addresses from a block supplied by IANA.

Migration of the wire format
----------------------------

Eventually we will want to update the wire format to replace the current ISD-AS-128bitHOST
addresses with plain V6 addresses. A possible migration plan would be:

1. Keep the address representation in code unchanged (ie. ISD-AS-HOST components, full
   sized), and add the proper, parametrized, encoding/decoding layer between the code and
   the wire format. That code follows the same configuration as that used at the API, with
   one additional option to emit the legacy wire format entirely unchanged.
2. Between 0 and 100% of hosts can process the new format but emit the legacy format.
3. 100% can process the new format. Between 0 and 100% of host are configured to emit the
   new format.
4. 100% of hosts use the new format. The legacy code can be deleted when convenient.

It might prove helpful to extend the internal (componentized) address representation to
include the IPV6 prefix that is part of the native V6 representation.

Implementation
==============

(This section, is not finished - just an intro).

Considering only the transition to using V6 addresses at the API:

The thing currently most ressembling a SCION API is the snet package. The snet API, as it
currently is does not allow the use of addresses as opaque entities. The application is
expected to openly manipulate address components, find a route, and even connect to the
border router by itself. Under these conditions it not even possible to initiate the
transition to V6 addresses for our own client code (i.e. the control server, ping, others?). 

So, to make that possible we must first give our application some API that allows them
to treat an address as just that: a bunch of random bits plus, may be a port; something
equivalent to bind([addr]), connect(addr [,routespec]), or sendto(addr, stuff, [,routespec]),
where addr does not need to include the next hop and where routespec is entirely optional.

Once we have that, we can start enabling the use of V6 addresses as the addr argument.

The netsec tree also offers a number of scion-enabled apps. Those rely on "pan", a custom
API-like layer. It would be good to try and converge pan and the new API contemplated
above, so that eventually, these scion-enabled apps are able to use plain IPV6 addresses
too.

