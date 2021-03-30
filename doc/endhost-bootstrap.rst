********************************
Automated end host bootstrapping
********************************

This file documents the design of the end host bootstrapping.

- Author(s): Andrea Tulimiero, François Wirz
- Last updated: 2021-03-09
- Status: draft

Overview
========

Low entry barriers are crucial to push people to experiment with new
technologies.
The goal of automated end host bootstrapping is to let anyone join the
SCION internet effortlessly.
From within an AS, all an end user needs to do is to install a package.

In particular, the package contains a bootstrapper daemon that retrieves
hints from the local network using `zero conf` services, downloads the
required SCION configuration files from a local discovery server, and starts
the SCION Daemon (SD).

Terminology
-----------

A **hint** is a piece of information returned by a `zero conf` service deployed
in the local network.
Depending on the discovery mechanism, a hint can be either sufficient to contact
a discovery server (e.g., providing its IP address) or can be used to query the local
network further (e.g., a DNS PTR response).

A **discovery** **server** is a server that exposes the endpoints required
by the bootstrapper (more in the `Discovery Server`_ section).

A **discoverer** is a client of a `zero conf` service. It communicates with the service
and provides hints to the bootstrapper.

Design
======

Bootstrapping Process
---------------------

An external orchestrator (e.g., *systemd*) will manage the bootstrapper
daemon and start the SD once the bootstrapper finishes successfully.

Bootstrapping Steps
^^^^^^^^^^^^^^^^^^^

The bootstrapping process consists of the following:

1. The bootstrapper daemon probes the local network for hints about a
   discovery server address using the available discovery mechanisms (i.e., DHCP, DNS, and mDNS).
2. Wait for hints from discoverers.
3. Once a hint gets received, the bootstrapper tries to download the topology of
   the AS and some TRCs from the discovery server. While there is no maximum amount of TRCs to
   be served, the discovery server must provide at least the TRC of the ISD the AS is in.

   a. On success, the bootstrapper prepares the SD's files and exits successfully, and the SD is automatically started by the orchestrator.
   b. On failure, go back to 2.


If no hint is received after a certain period, the bootstrapper times out
and exits with a non-zero value.

NB: The TRCs retrieval is a temporary solution; in the future, they will be
installed on a device via other means, ideally before it gets connected to
a network at all (more in the `Security`_ section).

Discovery Mechanisms
--------------------

In this section, we analyze the various discovery mechanisms supported
by the bootstrapper.
For clarity's sake, we suppose the following setting:

- the end host is located in the ``example.com`` domain, and
- the IP address of the discovery server serving the bootstrapping files can
  be reached at ``192.168.1.1``.

DHCP
^^^^

The DHCP mechanism requires a DHCP server present in the network.

The DHCP server has to be configured to announce the addresses of the discovery services
in the option field with ID 72 ”Default WWW server”, in our example ``192.168.1.1``.
We chose this existing option to ease rapid development without going through a formal standardization
at IETF and because we use the same application-level protocol as used in the WWW, namely HTTP.

This mechanism is a simple one for small networks, covering scenarios such as household networks.
The drawback is that only an IP address can be announced via this mechanisms and hence a default port needs to be used.

A more advanced solution is to use a DHCP Vendor-Identifying Vendor Option as defined in [RFC3925]_.
The enterprise number used to identify the option is the Private Enterprise Number
assigned to Anapaya Systems, PEN 55324.
The option has the following format::

      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  option-code  |  option-len   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      enterprise-number1       |
    |                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   data-len1   |               |
    +-+-+-+-+-+-+-+-+               |
    /      vendor-class-data1       /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

The IP address and the port of the discovery server are encoded as a sequence of code/length/value fields
as defined in RFC2132 section 2 "DHCP Option Field Format".
An IPv4 address is encoded as a 4 byte sequence with type code 1.
A UDP port is encoded as a 2 byte sequence with type code 2.
The option fields have the following general format::

     Code   Len   Vendor-specific information
    +-----+-----+-----+-----+---     ---+-----+
    |  tc |  n  |  i1 |  i2 | ...   ... |   in|
    +-----+-----+-----+-----+---     ---+-----+

DNS
^^^

The DNS-based mechanisms require public DNS to be set up to contain the necessary records.

Some minimal setups are listed below:

*DNS SRV*

As specified in [RFC2782]_, a DNS SRV record redirects to an ``A`` record pointing to the discovery server:

- ``_sciondiscovery._tcp.example.com IN SRV 8041 sciondiscovery.example.com``
- ``sciondiscovery.example.com IN A 192.168.1.1``

*DNS-SD*

As specified in [RFC6763]_, a list of DNS PTR records points to SRV records,
each of which defines an instance of a SCION discovery service:

- ``_sciondiscovery._tcp.example.com IN PTR SCI-ED._sciondiscovery._tcp.example.com``
- ``SCI-ED._sciondiscovery._tcp.example.com IN SRV 8041 scied-sciondiscovery.example.com``
- ``scied-sciondiscovery.example.com IN A 192.168.1.1``

*DNS-NAPTR*

In this variant, a DNS NAPTR record redirects to an ``A`` record pointing to the
discovery server:

- ``example.com IN NAPTR "A" "x-sciondiscovery:tcp" "" sciondiscovery.example.com``
- ``sciondiscovery.example.com IN A 192.168.1.1``

Like the DNS-SD option, multiple NAPTR records for different discovery services
can be defined.

This mechanism is well suited for large-scale networks having control over their DNS domain.
Supporting both of them gives network operators more flexibility to choose depending on their DNS setup.

mDNS
^^^^

mDNS, a decentralized DNS based on IP multicasting, is usually used
in combination with DNS-SD to realize *zero conf* networks.
It removes the need for a centralized DNS server, but it might not be
easy to correctly set up a network to work with multicast traffic.
It is a lightweight solution that requires just one entity besides the client in the network.
On the one hand, mDNS is a very lightweight and simple solution to deploy.
However, when planning to deploy mDNS, one must keep in mind that it relies on IP multicast communication.
If all participating hosts reside in the same network, this should raise no issue; however, if the network is divided by a router,
between the clients and the discovery server, the router has to be configured to propagate multicast traffic
between the two subnets for the discovery to work.

This mechanism is quite flexible and can be used in almost every scenario.
However, since devices need to be in the same subnet to discover each other it does not work well with a large,
segmented enterprise network.

Discovery Server
----------------

The discovery server (e.g. *Nginx*) exposes the following endpoints to
serve the bootstrapping configuration files:

- ``/topology``: to retrieve the topology of the AS, and
- ``/trcs/isd{isd}-b{base}-s{serial}`` and ``/trcs/isd{isd}-b{base}-s{serial}/blob``:
  to retrieve the TRCs needed by the SD.

The API and parameter values are the same as described
in [spec/control/spec.yml](https://github.com/scionproto/scion/tree/master/spec/control/spec.yml).

NB: The endpoints are kept separate since in the future the latter should no
longer be used for bootstrapping.  As previously pointed out, the TRCs will be
installed on a device via different out-of-band means.


Security
========

Guaranteeing the genuinity of the retrieved resources is crucial to ensure that
a user's connection is not hijacked. To certify a resource, this resource can be signed
so that after the download the bootstrapper can verify its authenticity.

In the current Internet, the root of trust is based on an oligopoly of CAs.
In SCION, this root of trust is represented by one TRC per ISD.
Nonetheless, like the current Internet, a device joining a network for the first time
needs to have some pre-shared knowledge to determine what is authentic or not.

While we can consider the discovery of TRCs a temporary solution, the same is not true for the
topology -- which is at the heart of the automatic bootstrapping.
For this, a signing solution based on the cryptographic keys of an AS should be implemented.

The bootstrapper has a config option to allow it to download the TRC from the
local AS infrastructure.
Only this initial TRC retrieval is allowed to be unauthenticated, under the
Trust on first use (TOFU) principle, and subsequent requests must be
authenticated and the user warned if the there is a conflict with an existing
TRC.
Otherwise, a user needs to copy a TRC to a well-known location on the system.

Request for Comments
====================

1. All discovery mechanisms can provide the port in addition to the discovery
   server IP. When the port is not provided a default port value of 8041 is
   assumed.
2. The DNS discovery mechanisms use the name server and DNS search domain
   values provided by the host OS. This covers the case where a static network
   configuration is used and no DHCP server is available on the local network.
   When DHCP discovery is enabled those values can additional be retrieved over
   DHCP, covering the case where the host uses name servers and DNS search
   domains not specific to the local network, like the public recursive name
   servers ``1.1.1.1`` or ``9.9.9.9`` and search domain ``.local``.

References
==========

.. [RFC2782] https://tools.ietf.org/html/rfc2782
.. [RFC6763] https://tools.ietf.org/html/rfc6763
.. [RFC3925] https://tools.ietf.org/html/rfc3925


