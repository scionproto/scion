***************
Common settings
***************

Configuration
=============

The general pattern for the long-running SCION services (:doc:`router`, :doc:`control`,
:doc:`gateway`, :doc:`daemon`), is to load a :ref:`.toml <common-conf-toml>` configuration file
which is specified with a ``--config`` option when starting the service.
This configuration file specifies all options for running the service, in particular the
**configuration directory** from which all other configuration files are read.

The set of required configuration files differs between the applications. The configuration files
are organized specifically to allow sharing the configuration directory between different services.

.. _common-conf-toml:

Common configuration .toml
---------------------------

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


.. _common-conf-topo:

topology.json
-------------

The ``topology.json`` file of an AS specifies all the inter-AS connections to neighboring ASes, and
defines the underlay IP/UDP addresses of services and routers running in this AS.

First, the structure of the configuration is presented as a pseudo-JSON.
The more detailed explanation of the individual fields can be found below.

..
   Note: use YAML syntax highlighting for JSON because this allows annotation comments and
   accidentally gives pretty nice coloring for placeholders.

.. code-block:: yaml

   {
      "isd_as": <isd-as>,
      "attributes" = [<"core">?]
      "mtu": <int>,
      "border_routers": {
         <router-id>: {
            "internal_addr": <ip:port>,
            "interfaces": {
               # ... interfaces definitions ... (see below)
            }
         }
         # ...
      },
      "control_service": {
         <cs-id>: {
            "addr": <ip:port>
         }
         # ...
      },
      "discovery_service": {
         <ds-id>: {
            "addr": <ip:port>
         }
         # ...
      },
   }

Each ``interfaces`` entry defines one inter-domain link to a neighboring AS.

.. code-block:: yaml

   <interface-id>: {
      "isd_as": <neighbor-isd-as>,
      "link_to": <"parent"|"child"|"peer"|"core">,
      "mtu": <int>,
      "underlay": {
         "public": <ip:port>,
         "bind": <ip>,
         "remote": <ip:port>,
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

   Role of this AS. ``["core"]`` for core-ASes, ``[]`` for non-core ASes.

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

   .. option:: internal_addr = <ip:port>, required

      UDP address on which the router receives SCION packets from
      sibling routers and end hosts in this AS.

   .. object:: interfaces

      .. object:: <interface-id>

         An interface ID is the AS-local identifier for an inter-domain link.

         The interface ID is an arbitrary number between 1 and 65535,
         assigned without external coordination by the operator of the AS.

         In this ``topology.json`` file, the ID is contained in a string.

      .. option:: isd_as = <isd-as>, required

         The ISD-AS of the neighboring AS.

      .. option:: link_to = "parent"|"child"|"peer"|"core", required

         Type of the relation to the neighbor AS.

         .. TODO
            Reference overview document that explains these link types.

      .. option:: mtu = <int>, required

         Maximum Transmission Unit in bytes for SCION packets (SCION headers and payload) on this
         link.


      .. object:: underlay, required for "self"

         Underlay specifies the local addresses used for the underlay IP/UDP connection to the
         neighbor router.
         These addresses are only relevant to the router that operates this link, i.e. the router
         instance with :option:`general.id <router-conf-toml general.id>` matching
         :option:`<router-id> <topology-json <router-id>>`.


         The :option:`underlay.public <topology-json public>` is the address of this side of the link,
         while :option:`underlay.remote <topology-json remote>` is the address of the remote side of the link.

         In the configuration for the corresponding interface in the neighbor AS, these
         addresses are exactly swapped.

         .. option:: public = <ip:port>, required

            The IP/UDP address of this router interface.

         .. option:: bind = <ip>, optional

            IP address to which the router should :manpage:`bind(2)`.

            This can optionally override the the IP in :option:`public <topology-json public>`,
            for the case that router instance is running in a container, a VM, or generally any kind
            of NAT.
            If NAT occurs, :option:`public <topology-json public>` is the address of
            the interface as seen by the neighbor router, while bind is the local address.

         .. option:: remote = <ip:port>, required

            The IP/UDP address of the corresponding router interface in the neighbor AS.

      .. option:: bfd, optional

         :term:`Bidirectional Forwarding Detection (BFD) <BFD>` is used to determine
         the liveness of the link by sending BFD control messages at regular intervals.

         These settings are only relevant to the router that operates this link, i.e. the router
         instance with :option:`general.id <router-conf-toml general.id>` matching
         :option:`<router-id> <topology-json <router-id>>`.

         .. option:: disable = <bool>, default false

            Disable BFD, unconditionally consider the connection alive.

            Takes precedence over :envvar:`SCION_EXPERIMENTAL_BFD_DISABLE`.

         .. option:: detect_mult = <uint8>, default 3

            After ``detect_mult`` consecutively missing control packets, the BFD session is
            considered "down" and is reset.

            Takes precedence over :envvar:`SCION_EXPERIMENTAL_BFD_DETECT_MULT`.

         .. option:: desired_min_tx_interval = <duration>, default 200ms

            Defines the frequency at which this router should send BFD control messages for this
            inter-domain link.
            The effective interval is the result of negotiating with the remote router during
            session establishment;
            the value will be ``max(desired_min_tx_interval, remote.required_min_rx_interval)``.

            Takes precedence over :envvar:`SCION_EXPERIMENTAL_BFD_DESIRED_MIN_TX`.

         .. option:: required_min_rx_interval = <duration>, default 200ms

            Defines an upper bound for the frequency at which this router wants to receive BFD
            control messages for this inter-domain link.
            The effective interval at which the remote router will send control messages is the
            result of negotiating with the remote router during session establishment;
            the value will be ``max(remote.desired_min_tx_interval, required_min_rx_interval)``.

            Takes precedence over :envvar:`SCION_EXPERIMENTAL_BFD_REQUIRED_MIN_RX`.

.. option:: control_service

   .. option:: <cs-id>

      Identifier for a control service instance.
      Matches the :option:`general.id <cs-conf-toml general.id>` of a control service instance.

   .. option:: addr = <ip:port>, required

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

   .. option:: addr = <ip:port>, required

      See ``control_service.addr``, above.
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
