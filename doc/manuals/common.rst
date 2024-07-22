*************
Configuration
*************

The general pattern for the long-running SCION services (:doc:`router`, :doc:`control`,
:doc:`gateway`, :doc:`daemon`), is to load a :ref:`.toml <common-conf-toml>` configuration file
which is specified with a ``--config`` option when starting the service.
This configuration file specifies all options for running the service, in particular the
**configuration directory** from which all other configuration files are read.

The set of required configuration files differs between the applications. The configuration files
are organized specifically to allow sharing the configuration directory between different services.

.. _common-conf-toml:

Configuration .toml
===================

This configuration is a `TOML <https://toml.io/en/>`_-file.

The following options are implemented by all applications.

.. program:: common-conf-toml

.. object:: log

   .. option:: log.console.level = "debug"|"info"|"error" (Default: "info")

      Log level at startup.

      The log level can be changed at runtime via the :ref:`HTTP API <common-http-api>`.

   .. option:: log.console.format = "human"|"json" (Default: "human")

      Encode the log either in a human oriented form or json.

   .. option:: log.console.disable_caller = <boolean>

      If ``true``, disable annotating logs with the calling function's file name and line number.
      By default, all logs are annotated.


.. object:: metrics

   .. option:: metrics.prometheus = <string>

      Address on which to export the :ref:`common HTTP API <common-http-api>`, in the form
      ``host:port``, ``ip:port`` or ``:port``.
      The eponymous prometheus metrics can be found under ``/metrics``, but other endpoints
      are always exposed as well.

      If not set, the HTTP API is not enabled.

.. _common-conf-toml-db:

Database Connections
--------------------

The services use different SQLite database files, with paths and advanced connection options
configured individually.
The pattern is:

.. object:: some_db

   .. option:: some_db.connection = <string>

      File path or `SQLite URI <https://www.sqlite.org/uri.html>`_ for SQLite database.

   .. option:: some_db.max_open_conns = <int> (Default: 1)

      Sets sets the maximum number of open connections to the database.

      This **should** be left at 1 for SQLite databases.

   .. option:: some_db.max_idle_conns = <int> (Default: 2)

      Sets the maximum number of connections in the idle connection pool.
      If this value is higher than :option:`max_open_conns <common-conf-toml some_db.max_open_conns>`,
      then the effective value is the same as :option:`max_open_conns <common-conf-toml some_db.max_open_conns>`.

      This **should** be left > 0 for SQLite databases, in particular
      if an `in-memory database <https://www.sqlite.org/inmemorydb.html>`_ is used.

.. _common-conf-topo:

topology.json
=============

The ``topology.json`` file of an AS specifies all the inter-AS connections to neighboring ASes, and
defines the underlay IP/UDP addresses of services and routers running in this AS.
The topology information is needed by :doc:`router` and :doc:`control` instances, and also by
end-host applications (including the :doc:`gateway`) which usually obtain it indirectly from the
:doc:`daemon` running on the same host.

.. Note::

   The topology.json configuration file contains information that is not relevant for all consumers
   of the file.

   For the sake of simplicity, you can use the same topology.json file on all SCION components
   within the SCION AS. In more advanced configurations, an extract of the topology.json file can be
   presented to each specific component.

The structure of the configuration is presented as a pseudo-JSON with a more detailed explanation
of the individual fields below.

..
   Comment: use YAML syntax highlighting for JSON because this allows annotation comments and
   accidentally gives pretty nice coloring for placeholders.

.. code-block:: yaml
   :caption: Pseudo-JSON description of the structure of the ``topology.json`` configuration file.
   :name: topology-json-structure

   {
      "isd_as": <isd-as>,
      "attributes" = [<"core">?]
      "mtu": <int>,
      "border_routers": {
         <router-id>: {
            "internal_addr": <ip|hostname>:<port>,
            "interfaces": {
               # ... interfaces definitions ... (see below)
            }
         }
         # ...
      },
      "control_service": {
         <cs-id>: {
            "addr": <ip|hostname>:<port>
         }
         # ...
      },
      "discovery_service": {
         <ds-id>: {
            "addr": <ip|hostname>:<port>
         }
         # ...
      },
   }

.. code-block:: yaml
   :caption: Each ``interfaces`` entry defines one inter-domain link to a neighboring AS.
   :name: topology-json-interface-entry

   <interface-id>: {
      "isd_as": <neighbor-isd-as>,
      "link_to": <"parent"|"child"|"peer"|"core">,
      "mtu": <int>,
      "underlay": {
         "local": "<ip|hostname>:<port>", # or just ":<port>"
         "remote": "<ip|hostname:port>",
      },
      "bfd": {              # optional
         "disable": <bool>,
         "detect_mult": <uint8>,
         "desired_min_tx_interval": <duration>,
         "required_min_rx_interval": <duration>
      }
   }

.. program:: topology-json

.. option:: isd_as = <isd-as>, required

   The ISD-AS of this AS.

.. option:: attributes = [<"core">?], default []

   Role of this AS. ``["core"]`` for core ASes, ``[]`` for non-core ASes.

   .. Note::

      Historical relict; there used to be multiple different attributes ("core", "issuing",
      "authoritative", "voting") which could apply a more fine granular role configuration. This
      functionality has moved into different places, only "core" remains.

.. option:: mtu = <int>, required

   Common Maximum Transmission Unit in bytes for SCION packets (SCION headers and payload)
   for intra-AS connections.
   This is the minimum MTU between any two internally connected border router interfaces.

.. object:: border_routers

   .. option:: <router-id>

      Identifier for a border router instance.
      Matches the :option:`general.id <router-conf-toml general.id>` of a router instance.

   .. option:: internal_addr = <ip|hostname:port>, required

      UDP address on which the router receives SCION packets from
      sibling routers and end hosts in this AS.

   .. object:: interfaces

      .. option:: <interface-id>

         The :term:`interface ID <Interface ID>` for an inter-domain link.

         In this ``topology.json`` file, the ID is contained in a string.

      .. _topology-json-interface-isd_as:

      .. option:: isd_as = <isd-as>, required

         The ISD-AS of the neighboring AS.

      .. option:: link_to = "parent"|"child"|"peer"|"core", required

         Type of the link relation to the neighbor AS.
         See :ref:`overview-link-types`.

      .. option:: remote_interface_id = <int>

         The :term:`interface ID <Interface ID>` for the corresponding interface in the
         neighboring AS.

         This is required if, and only if, :option:`link_to <topology-json link_to>` is ``peer``.

         This ``remote_interface_id`` is used when announcing peering links as part of AS Entries in
         PCBs (see :ref:`control-plane-beaconing`).
         During :ref:`path-segment combination <control-plane-segment-combination>`, this interface
         ID, will then be used together with the ISD-AS to match up the peering entries from
         AS entries in different path segments.

         If ``remote_interface_id`` is set incorrectly, the peering entries cannot be matched up
         correctly, resulting in missing or broken end-to-end paths:

         - If the ``remote_interface_id`` does not match `any` interface ID used for peering links
           in the neighboring AS, the segment combination will not find paths making use of this
           interface.
         - If two ASes are connected by multiple peering links and ``remote_interface_id`` matches the
           `wrong` interface ID, an incorrect path may be constructed which will be rejected in the
           data plane (i.e. the routers will drop all packets).

      .. option:: mtu = <int>, required

         Maximum Transmission Unit in bytes for SCION packets (SCION headers and payload) on this
         link.

      .. object:: underlay, required for "self"

         Underlay specifies the local addresses used for the underlay IP/UDP connection to the
         neighbor router.
         These addresses are only relevant to the router that operates this link, i.e. the router
         instance with :option:`general.id <router-conf-toml general.id>` matching
         :option:`<router-id> <topology-json <router-id>>`.


         The :option:`underlay.local <topology-json local>` is the address of this side of the link,
         while :option:`underlay.remote <topology-json remote>` is the address of the remote side of the link.

         In the configuration for the corresponding interface in the neighbor AS, these
         addresses are exactly swapped.

         .. option:: remote = <ip|hostname>:<port>, required

            The IP/UDP address of the corresponding router interface in the neighbor AS.

         .. option:: local = [<ip|hostname>]:<port>, required

            The IP/UDP address of this router interface.
            The IP or hostname can be ommitted; in this case the router will just bind to a wildcard
            address.

         .. option:: public = <ip|hostname>:<port>, deprecated

            The IP/UDP address of this router interface.

            .. admonition:: Deprecated
               :class: caution

               Replaced by :option:`underlay.local <topology-json local>`.

         .. option:: bind = <ip>, deprecated

            IP address of this router interface. Overrides IP of :option:`underlay.public <topology-json public>`.

            .. admonition:: Deprecated
               :class: caution

               Replaced by :option:`underlay.local <topology-json local>`.

      .. option:: bfd, optional

         :term:`Bidirectional Forwarding Detection (BFD) <BFD>` is used to determine
         the liveness of the link by sending BFD control messages at regular intervals.

         These settings are only relevant to the router that operates this link, i.e. the router
         instance with :option:`general.id <router-conf-toml general.id>` matching
         :option:`<router-id> <topology-json <router-id>>`.

         .. option:: disable = <bool>, default router.bfd.disable

            See :option:`router.bfd.disable <router-conf-toml disable>`.

            Disable BFD, unconditionally consider the connection alive.

         .. option:: detect_mult = <uint8>, default router.bfd.detect_mult

            See :option:`router.bfd.detect_mult <router-conf-toml detect_mult>`.

            After ``detect_mult`` consecutively missing control packets, the BFD session is
            considered "down" and is reset.

         .. option:: desired_min_tx_interval = <duration>, default router.bfd.desired_min_tx_interval

            See :option:`router.bfd.disired_min_tx_interval <router-conf-toml desired_min_tx_interval>`.

            Defines the frequency at which this router should send BFD control messages for this
            inter-domain link.
            The effective interval is the result of negotiating with the remote router during
            session establishment;
            the value will be ``max(desired_min_tx_interval, remote.required_min_rx_interval)``.

         .. option:: required_min_rx_interval = <duration>, default router.bfd.required_min_rx_interval
            See :option:`router.bfd.required_min_rx_interval <router-conf-toml required_min_rx_interval>`.

            Defines an upper bound for the frequency at which this router wants to receive BFD
            control messages for this inter-domain link.
            The effective interval at which the remote router will send control messages is the
            result of negotiating with the remote router during session establishment;
            the value will be ``max(remote.desired_min_tx_interval, required_min_rx_interval)``.

.. option:: control_service

   .. option:: <cs-id>

      Identifier for a control service instance.
      Matches the :option:`general.id <control-conf-toml general.id>` of a control service instance.

   .. option:: addr = <ip|hostname>:<port>, required

      The address of the control service. This is *both* a UDP and TCP address;

      * The UDP address is the underlay address for the control service's anycast address.
        This is used when communicating with control services in other SCION ASes, using SCION.
      * The TCP address is used to serve the grpc API to end hosts in the local AS.

.. option:: discovery_service

   .. option:: <ds-id>

      Identifier for a discovery service instance.

      .. Hint::

         The implementation of the discovery service is part of the control service.
         This usually points to a control service instance.

   .. option:: addr = <ip|hostname>:<port>, required

      See ``control_service.addr``, above.

.. _common-conf-duration:

Duration Format
===============

Where duration values are loaded from configuration options, the following format is expected:

.. code-block::

   [\-0-9]+(y|w|d|h|m|s|ms|us|µs|ns)

The unit suffixes have their usual meaning of ``y`` year, ``w`` week, ``d`` day, ``h`` hour,
``m`` minute, ``s`` second, ``ms`` millisecond, ``us`` or ``µs`` microsecond, and ``ns`` nanosecond.

Mixed unit durations are not supported (e.g. ``1h10m10s`` is not supported).
The long duration units are simple factors, not calendar offsets:

- ``d`` is always 24 hours
- ``w`` is always 7 days
- ``y`` is always 365 days

.. _common-http-api:

HTTP API
========

**Known issue**. If an unknown route is accessed (e.g., ``/this-does-not-exist``), the HTTP
reply will respond as if the ``/`` route were used and print an HTML page with links to
all exposed APIs. This response will have a 200 (OK) HTTP Status Code.

The following APIs are exposed by most applications:

- ``/``: (**EXPERIMENTAL**)
  - Method **GET**. Returns an HTML page containing links to exposed APIs.

- ``/config``: (**EXPERIMENTAL**)

  - Method **GET**. Prints the TOML representation of the config the application
    is currently using.

- ``/info``: (**EXPERIMENTAL**)

  - Method **GET**. Prints a plaintext representation of general information about
    the application. Amongst others, the information includes version,
    process ID, and user/group IDs.

- ``/log/level``: (**EXPERIMENTAL**)

  - Method **GET**: Returns the current logging level, in JSON.
  - Method **PUT**: Sets the current logging level. Either JSON or URL encoded
    request body is supported.For example, to set the logging level to ``debug``
    run:

    .. code-block:: bash

       curl -X PUT "http://172.20.1.3:30442/log/level" -d level=debug
       curl -X PUT "http://172.20.1.3:30442/log/level" -H "Content-Type: application/json" -d '{"level":"debug"}'

    If the content type is set to ``application/x-www-form-urlencoded`` (curl
    default), the endpoint expects a URL encoded request body. In all other
    cases, a JSON encoded request body is expected.

- ``/metrics``:

  - Method **GET**: Returns the Prometheus metrics exposed by the application.

- ``/debug/pprof``:

  - Serves runtime profiling data in the format expected by the pprof visualization tool.
    See `net/http/pprof <https://golang.org/pkg/net/http/pprof/>`_ for details on usage.
