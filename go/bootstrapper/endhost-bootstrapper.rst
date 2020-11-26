**********************
End host bootstrapping
**********************

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

We use **Systemd** to orchestrate the bootstrapping process: managing the
bootstrapper daemon; and guaranteeing the sequentiality constraints of the
SD with respect to the bootstrapper daemon.
In fact, the SD must start only after the bootstrapper exited successfully.

In the remainder of this section, we assume that the dispatcher, the
bootstrapper, and the sciond service units are all enabled and running.

The bootstrapping process consists of the following:

1. The bootstrapper daemon probes the local network for hints about the
   web server address using the available discovery mechanisms (i.e., DHCP , DNS and mDNS).
2. Once a hint gets received, the bootstrapper tries to download the topology of
   the AS and some TRCs from the hinted local web server.
3. If the retrieval is successful, the bootstrapper prepares the SD's files and
   exits successfully, and the SD is automatically started by Systemd.
4. Otherwise, the bootstrapper tries to contact the web server specified by the next hint.
5. If no hint is received after a certain span of time, the bootstrapper
   times out and exit with a non-zero value.

NB: The TRCs retrieval is a temporary solution; in the future, they will be
installed on a device via other means, ideally before it gets connected to
a network at all.

SD files creation
^^^^^^^^^^^^^^^^^

Once retrieved the topology JSON file and the TRCs archive, the bootstrapper
moves the former to ``/etc/scion/topology.json``, and the content of the
latter to ``/etc/scion/certs/``.
If an SD alternative configuration file is specified, in the configuration of 
the bootstrapper, the bootstrapper copies this file to ``/etc/scion/sd.toml``.

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

We choose *Nginx* for the web server to serve the bootstrapping configuration files -- obviously, this can be achieved with any other web server.

The endpoints exposed by the web server are the following:

- ``/scion/discovery/<version>/topology.json``: to retrieve the topology of
  the AS, and
- ``/scion/discovery/<version>/trcs.tar.gz``: to retrieve the TRCs needed by the SD.

NB: The endpoints are kept separate since in the future the latter will be removed.
As previously pointed out, the TRCs will be installed on a device via different
means.

Minimal configuration files
===========================

Systemd service units
---------------------

Bootstrapper
^^^^^^^^^^^^

A minimal example of the bootstrapper service units ``scion-bootstrapper@.service``.

.. code-block:: toml

  [Unit]
  After=network-online.target
  Before=scion-daemon@%i.service
  Wants=network-online.target

  [Service]
  Type=oneshot
  WorkingDirectory=/etc/scion/
  ExecStartPre=/bin/mkdir -p /etc/scion/certs/
  ExecStartPre=/bin/cp /etc/scion/boot.toml /etc/scion/boot-%i.toml
  ExecStartPre=/bin/sed -i s#NIC#%i#g /etc/scion/boot-%i.toml
  ExecStart=/opt/scion/bootstrapper -config boot-%i.toml
  RemainAfterExit=True

  # Raw network is needed for DHCP
  AmbientCapabilities=CAP_NET_RAW

SCIOND
^^^^^^

A minimal example of the sciond service units ``scion-daemon-bootstrap@.service``.

.. code-block:: toml

  [Unit]
  After=network-online.target scion-bootstrapper@%i.service scion-dispatcher.service
  BindsTo=scion-bootstrapper@%i.service
  Wants=network-online.target

  [Service]
  Type=simple
  WorkingDirectory=/etc/scion/
  ExecStartPre=/bin/mkdir -p /etc/scion/gen-cache /var/cache/scion /run/shm/sciond
  ExecStart=/opt/scion/sciond --config /etc/scion/sd.toml

DNS
---

mDNS
^^^^

A simple mDNS configuration can be achieved using *Avahi* with the following configuration:
 
.. code-block::xml

  <?xml version="1.0" standalone='no'?>
  <!DOCTYPE service-group SYSTEM "avahi-service.dtd">
  <service-group>
    <name replace-wildcards="yes">%h</name>
      <service>
          <type>_sciondiscovery._tcp</type>
          <port>8041</port>
      </service>
  </service-group>

Nginx site
----------

::

  server {
          listen 8041 default_server;
          listen [::]:8041 default_server;

          location / {
                  root /srv/http/;
                  autoindex on;
                  autoindex_format json;
          }
  }


After having installed Nginx, the network admin can follow these steps to expose the endpoints needed by the bootstrapper:

- copy the site configuration to ``/etc/nginx/sites-available`` and enable it by creating
  a link that points to ``/etc/nginx/sites-available/scion`` in ``/etc/nginx/sites-enabled``,
- create a link to the topology at ``/srv/http/scion/discovery/v1/topology.json``, and
- create a link to a *tar.gz* archive containing the TRCs to serve at
  ``/srv/http/scion/discovery/v1/trcs.tar.gz``.

Security
========

Request for Comments
====================

Unlike the DHCP option, the DNS SRV record can specify a port to reach the 
service. Currently, if the port is not the canonical one, currently the 8041,
the hint is discarded.
Do we want this behavior?
In my opinion this should be changed.

References
==========

.. [RFC2782] https://tools.ietf.org/html/rfc2782
.. [RFC6763] https://tools.ietf.org/html/rfc6763


