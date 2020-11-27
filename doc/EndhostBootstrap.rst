******************
End host bootstrap
******************

This file documents the design of the end host bootstrapping.

Overview
========

Low entry barriers are crucial to push people to experiment with new
technologies.
The goal of the automated end host bootstrapping is to let anyone joining the
SCION internet effortlessly.
From within an AS, all an end user needs to do is installing a package.

In particular, the package contains a bootstrapper daemon that retrieves
hints from the local network using `zero conf` services, downloads the
required SCION configuration files from a local web server, and starts
the SCION Daemon (SD).

..
 image:: fig/hidden_paths/HiddenPath.png

Design
======

Bootstrapping process
---------------------

An external orchestrator (e.g., *Systemd*) shall take care of: managing the
bootstrapper daemon; and start the SD once the bootstrapper exits
successfully.

In the remainder of this section, we assume that the dispatcher, the
bootstrapper, and the SD services are all enabled.

The bootstrapping process consists of the following:

1. The bootstrapper daemon probes the local network for hints about the
   web server address using the available discovery mechanisms (i.e., DHCP , DNS and mDNS).
2. Wait for hints from discoverers.
3. Once a hint gets received, the bootstrapper tries to download the topology of
   the AS and some TRCs from the hinted local web server.

   a. On success, the bootstrapper prepares the SD's files and exits successfully, and the SD is automatically started by the orchestrator.
   b. On failure, the bootstrapper tries to contact the web server specified by the next hint (go back to 2).

If no hint is received after a certain span of time, the bootstrapper times out
and exits with a non-zero value.

NB: The TRCs retrieval is a temporary solution; in the future, they will be
installed on a device via other means, ideally before it gets connected to
a network at all.

SD files creation
^^^^^^^^^^^^^^^^^

Once retrieved the topology JSON file and the TRCs archive, the bootstrapper
moves the former to ``<scion_folder>/topology.json``, and the content of the
latter to ``<scion_folder>/certs/``.
If an SD alternative configuration file is specified, in the configuration of 
the bootstrapper, the bootstrapper copies this file to ``<scion_folder>/sd.toml``.

If not specified differently, ``<scion_folder>`` defaults to ``/etc/scion``.

Discovery mechanisms
--------------------

In this section, we analyze the various discovery mechanisms supported
by the bootstrapper.
For clarity's sake, we suppose the following setting:

- the end host is located in the ``ethz.ch`` domain, and
- the IP address of the web server serving the bootstrapping files can
  be reached at ``192.33.93.173``.

DHCP
^^^^

This mechanisms consists of adding a Default World Wide Web server option
(72) to the DHCP server of the network, whose content is ``192.33.93.173``.

DNS
^^^

Various discovery mechanisms are based on DNS, each one with its pros and cons.

*DNS SRV*

As specified in [RFC2782]_, a DNS SRV record redirects to an ``A`` record pointing to the web server:

- ``_sciondiscovery._tcp.ethz.ch IN SRV 8041 sciondiscovery.ethz.ch``
- ``sciondiscovery.ethz.ch IN A 192.33.93.173``

*DNS-SD*

As specified in [RFC6763]_, a list of DNS PTR records point to SRV records,
each of which define an instance of a SCION discovery service:

- ``_sciondiscovery._tcp.ethz.ch IN PTR SCI-ED._sciondiscovery._tcp.ethz.ch``
- ``SCI-ED._sciondiscovery._tcp.ethz.ch IN SRV 8041 scied-sciondiscovery.ethz.ch``
- ``scied-sciondiscovery.ethz.ch IN A 192.33.93.173``

*DNS-NAPTR*

In this variant, a DNS NAPTR record redirects to an ``A`` record pointing to the
web server:

- ``ethz.ch IN NAPTR "A" "x-sciondiscovery:tcp" "" sciondiscovery.ethz.ch``
- ``sciondiscovery.ethz.ch IN A 192.33.93.173``

Like the DNS-SD option, multiple NAPTR records for different discovery services
can be defined.

mDNS
^^^^

mDNS, a decentralized DNS based on IP multicasting, is usually used
in combination with the DNS-SD paradigm to achieve *zero conf* networks.
It removes the need of a centralized DNS server, but it might not be 
easy to correctly setup a network to work with multicast traffic.

Web server
----------

The web server (e.g. *Nginx*) shall expose the following endpoints to erve the bootstrapping configuration files:

- ``/scion/discovery/<version>/topology.json``: to retrieve the topology of
  the AS, and
- ``/scion/discovery/<version>/trcs.tar``: to retrieve the TRCs needed by the SD.

NB: The endpoints are kept separate since in the future the latter will be removed.
As previously pointed out, the TRCs will be installed on a device via different
means.


Security
========

**TBD**

Request for Comments
====================

1. Unlike the DHCP option, the DNS SRV record can specify a port to reach the
   service. Currently, if the port is not the canonical one, currently the 8041,
   the hint is discarded.
   Do we want this behavior?
   In my opinion this should be changed.
2. The name server the DNS discovery mechanisms uses is now retrieved via DHCP,
   instead of looking it up locally (since most likely it has been already
   retrieved with the DHCP exchange when the device obtained an IP address).
   The was motivation for this was to be OS independent.
   Do we want to keep this behavior?

References
==========

.. [RFC2782] https://tools.ietf.org/html/rfc2782
.. [RFC6763] https://tools.ietf.org/html/rfc6763


