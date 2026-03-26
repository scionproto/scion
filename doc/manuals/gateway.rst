**********************
SIG (SCION-IP Gateway)
**********************

:program:`gateway` is the SCION-IP Gateway (SIG). It tunnels IP packets over SCION to support communication between hosts that do not natively run SCION. For the protocol specifications, see the :doc:`/sig`.

Command Line Reference
======================

.. program:: gateway

Synopsis
--------

:program:`gateway` [:option:`--config \<config.toml\> <gateway --config>` | :option:`help <gateway help>` | :option:`version <gateway version>`]

Options
-------

.. option:: --config <config.toml>

   Specifies the configuration file and starts the gateway.

.. option:: help, -h, --help [subcommand]

   Display help text for subcommand.

.. option:: version

   Display version information.

.. option:: sample [file]

   Display sample files.

   .. option:: config

      Display a configuration file sample.

.. option:: completion [shell]

   Generate the autocompletion script for :program:`gateway` for the specified shell.

   Run :option:`gateway help completion <gateway help>` for a list of the available shells.

   Run :option:`gateway help completion [shell] <gateway help>` for usage information on the
   autocomplete script for a particular shell.

Deployment Examples
===================

Basic SIG Pair
--------------

The simplest deployment uses a pair of SIGs to tunnel IP traffic between them. In this example, the two SIGs are respectively in AS ``1-ff00:0:110`` and AS ``1-ff00:0:111``.

Each SIG requires two configuration files, with an optional third:

1. **Gateway configuration** (``gateway.toml``): specifies the gateway id, addresses, and references to the policy files. Generate a starting point with :option:`gateway sample config <gateway sample>`.

2. **Traffic policy** (``traffic.policy``): defines which remote ASes to create tunneling sessions to and what IP prefixes are reachable through them. A minimal traffic policy for AS ``1-ff00:0:110``, declaring that ``10.2.0.0/24`` is reachable through AS ``1-ff00:0:111``::

     {
       "ASes": {
         "1-ff00:0:111": {
           "Nets": ["10.2.0.0/24"]
         }
       },
       "ConfigVersion": 1
     }

3. **Routing policy** (optional): controls which IP prefixes to accept and advertise via :ref:`SGRP <sgrp>`. See `Routing Policy File`_ for the full syntax.

The SIG in AS ``1-ff00:0:111`` needs a matching traffic policy pointing back to AS ``1-ff00:0:110`` and listing the prefixes reachable through it.

Once both SIGs are running, IP traffic matching the configured prefixes is automatically tunneled over SCION. Each SIG independently discovers remote SIGs via :ref:`SIG Discovery <sig-discovery>`, fetches their prefix announcements via :ref:`SGRP <sgrp>`, and creates tunneling sessions.

IP traffic must be routed to the SIG using standard IP routing. The SIG automatically installs routes on the machine it runs on, but other hosts in the local network require static routes pointing to the SIG. Dynamic routing mechanisms are not supported.

Multi-SIG Deployment
--------------------

An AS can run multiple SIGs. Each SIG is configured independently with its own gateway ID, addresses, and policy files.

To hint to remote ASes which SCION interfaces should be used to reach each gateway, use `Network prefix pinning`_. Each gateway can list its preferred interfaces via the ``allow_interfaces`` field in the topology file.

Sample Configuration
====================

Generate a sample configuration file with::

  gateway sample config > gateway.toml

The sample contains two TOML sections. The key options are summarized below
(run the command for the full output with detailed comments):

``[gateway]``
-------------

.. code-block:: toml

   # ID of the gateway (default "gateway")
   id = "gateway"

   # The traffic policy file.
   # (default "/etc/scion/traffic.policy")
   traffic_policy_file = "/etc/scion/traffic.policy"

   # The IP routing policy file. If not set, a default policy
   # that rejects all IP prefix announcements is used.
   # (default "")
   ip_routing_policy_file = ""

   # The bind address for control messages (SGRP discovery and prefix exchange).
   # (default ":30256")
   ctrl_addr = ":30256"

   # The bind address for encapsulated data traffic.
   # (default ":30056")
   data_addr = ":30056"

   # The bind address for path probes.
   # (default ":30856")
   probe_addr = ":30856"

- ``id``: Identifier for this gateway instance. Relevant when running multiple SIGs.
- ``traffic_policy_file``: Path to the traffic policy JSON that defines remote ASes and expected prefixes.
- ``ip_routing_policy_file``: Path to the routing policy that controls prefix acceptance and advertisement via :ref:`SGRP <sgrp>`. If empty, all prefix announcements are rejected.
- ``ctrl_addr``, ``data_addr``, ``probe_addr``: Bind addresses for the three SIG planes. If the host part is empty, the gateway infers it from the route to the control service.

``[tunnel]``
------------

.. code-block:: toml

   # Name of TUN device to create. (default "sig")
   name = "sig"

   # Source hint for IPv4 routes. (default "")
   src_ipv4 = "192.0.2.100"

   # Source hint for IPv6 routes. (default "")
   src_ipv6 = "2001:db8::2:1"

- ``name``: Name of the TUN device the gateway creates. IP packets read from this device are encapsulated and sent over SCION; packets received from SCION are decapsulated and written back to it.
- ``src_ipv4``, ``src_ipv6``: Source address hints IPv4/IPv6 routes added to the Linux routing table.

Nomenclature
============

.. include:: ./gateway/nomenclature.rst

Port table
==========

.. include:: ./gateway/port-table.rst

Metrics
=======

.. include:: ./gateway/metrics.rst

HTTP API
========

.. include:: ./gateway/http-api.rst

Routing Policy File
===================

.. include:: ./gateway/routing-policy.rst

Network prefix pinning
======================

.. include:: ./gateway/prefix-pinning.rst

Configuration
=============

In addition to the :ref:`common .toml configuration options <common-conf-toml>`, the gateway service
considers the following options.

.. object:: rpc

   .. option:: rpc.client_protocol = "grpc"|"connectrpc"|"all" (Default = "all")

      The rpc protocols that should be attempted when invoking the :program:`control` service.

   .. option:: rpc.server_protocol = "grpc"|"connectrpc"|"all" (Default = "all")

      The rpc protocols that should be supported by the :program:`gateway` service.
