*********************
Endhost bootstrapping
*********************

This file documents the design of the endhost bootstrapping.

Overview
========

Endhost bootstrapping makes joining the SCION internet from within an AS
as easy as installing a package.
The bootstrapper daemon retrieves hints from the local network using 
`zero conf` services, downloads the required SCION configuration files,
and starts the SCION Daemon (SD).

.. image:: fig/hidden_paths/HiddenPath.png

Design
======

In this section, we explore the overall design of the bootstrapper.

Systemd service units
---------------------

The orchestration of the bootstrapper and sciond, and their sequentiality requirements, 
is taken care by systemd.

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

Bootstrapping process
---------------------
In this section, we assume that the dispatcher, the bootstrapper, and the sciond
service units are all enable and running.

The bootstrapping process consists of:

1. The bootstrapper daemon probes the local network for hints using the available
   discovery mechanisms (i.e., DHCP, DNS-SD and mDNS).
2. Once a hint gets received, the bootstrapper tries to download the topology of
   the AS and some TRCs -- at least the one of the ISD the user is in, from the 
   hinted local web server.
3. The bootstrapper exits successfully and SD is automatically started by Systemd.

Discovery mechanisms
--------------------

DHCP
^^^^

DNS-SD
^^^^^^

mDNS
^^^^

Web server setup
---------------

We choose *Nginx* for the web server to host the bootstrapping configuration files.
Obviously, this can be achieved with any other web server.

Nginx site configuration
^^^^^^^^^^^^^^^^^^^^^^^^

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


After having installed Nginx, the network admin can follow these steps to expose the
endpoints needed by the bootstrapper:

- copy the site configuration to ``/etc/nginx/sites-available`` and enable it by creating
  a link that points to ``/etc/nginx/sites-available/scion`` in ``/etc/nginx/sites-enabled``,
- create a link to the topology at ``/srv/http/scion/discovery/v1/topology.json``, and
- create a link to a *tar.gz* archive containing the TRCs to serve at
  ``/srv/http/scion/discovery/v1/trcs.tar.gz``.

Security
--------

