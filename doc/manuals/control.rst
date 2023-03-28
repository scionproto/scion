***************
Control Service
***************

:program:`control` is the SCION control service.
It discovers SCION paths by particpating in the inter-domain path-dissemination process called
"beaconing".
It signs and validates the path information based on the :term:`Control-Plane PKI <CP-PKI>`.

In core ASes, the :program:`control` service also acts as the certificate authority from which ASes
in the local ISD request renewed certificates (or as a proxy thereof).

The :program:`control` service is also the recursive resolver for path information for endpoints in
the local AS.

Command line reference
======================

.. program:: control

.. option:: --config <config.toml>

   Specifes the :ref:`configuration file <control-conf-toml>` and starts the control service.

.. option:: help, -h, --help [subcommand]

   Display help text for subcommand.

.. option:: version

   Display version information.

.. option:: sample [file]

   Display sample files.

   .. option:: config

      Display a configuration file sample.

.. option:: completion [shell]

   Generate the autocompletion script for :program:`control` for the specified shell.

   Run :option:`control help completion <control help>` for a list of the available shells.

   Run :option:`control help completion [shell] <control help>` for usage information on the
   autocomplete script for a particular shell.

.. TODO
   add reference to control plane section

Environment variables
---------------------

.. envvar:: SCION_TESTING_DRKEY_EPOCH_DURATION

   For **testing only**.

   Override the global duration for :doc:`/cryptography/drkey` epochs.
   This can only work correctly if the same value is set for all connected control services in the
   test network.

   The format is a :ref:`duration <control-conf-duration>` with unit suffix (e.g. ``10s``).

Configuration
=============

The :program:`control` is configured with multiple files:

- the :ref:`.toml <control-conf-toml>` configures common features like logging and metrics and
  specifies the **configuration directory** from which all other configuration files are read.
- :ref:`topology.json <control-conf-topo>`, contains information about the inter-AS links
- :ref:`crypto/ and certs/ <control-conf-cppki>` contain :term:`CP-PKI` certificates and private keys
- :ref:`keys/ <control-conf-keys>` contains the AS's forwarding secret keys

.. _control-conf-toml:

Control service configuration
-----------------------------

In addition to the :ref:`common .toml configuration options <common-conf-toml>`, the control service
considers the following options.

.. program:: control-conf-toml

.. object:: general

   .. option:: general.id = <string> (Required)

      Identifier for this control service.

      This is used to identify which parts of the :ref:`control-conf-topo` file refer to self.
      Thus, ``id`` must match a key in the :ref:`control-conf-topo` files' ``control_service`` section.

   .. option:: general.config_dir = <string> (Required)

      Path to a directory containing the remaining configuration files.

      If this is a relative path, it is interpreted as relative to the current working directory of the
      program (i.e. **not** relative to the location of this .toml configuration file).

   .. option:: general.reconnect_to_dispatcher = <bool> (Default: false)

      Transparently reconnect to the dispatcher on dispatcher failure or restarts.

      .. Warning::
         This should be set to ``true``, unless your service orchestration ensures that
         failures of the dispatcher trigger a restart of :program:`control` also.

      .. TODO
         Change default to true!?

.. object:: quic

   .. option:: quic.address = <ip:port> (Optional)

      Local SCION address for inter-AS communication by QUIC/gRPC.
      By default, the address specified for this control service in its ``control_service`` entry of
      the :ref:`control-conf-topo` is used.

.. object:: features

   Features is a container for generic, boolean feature flags (usually for experimental or
   transitional features).

   .. option:: features.appropriate_digest_algorithm = <bool> (Default: false)

      Enables the CA module to sign issued certificates
      with the appropriate digest algorithm instead of always using ECDSAWithSHA512.

      **Transition**: This behaviour should be enabled unless there is a specific requirement to
      interface with older versions of SCION that don't support these certificates.
      The default for this flag will be change to ``true`` in future releases, and eventually
      removed.


.. object:: ca

   .. option:: ca.mode = "disabled"|"in-process"|"delegating" (Default: "disabled")

      Mode defines whether the :program:`control` should handle certificate issuance requests.
      This should be enabled in core-ASes that are labeled as ``issuing`` ASes in the :term:`TRC`.

      If set to ``in-process``, :program:`control` handles certificate issuance requests on its own.
      If set to ``delegated``, the certificate issuance is delegated to the service defined in
      :option:`ca.service <control-conf-toml ca.service>`.

   .. option:: ca.service

      Configuration for the CA service,
      effective with the :option:`ca.service <control-conf-toml ca.service>` mode ``delegated``.

      The CA service is expected to implement the API described by :file-ref:`spec/ca.gen.yml`.

      .. Hint::
         The `scionproto/scion <https://github.com/scionproto/scion>`_ project does not include such
         a CA Service implementation.

         Either use the built-in CA implementation (using :option:`ca.service = "in-process" <control-conf-toml ca.service>`)
         or create your own CA Service implementation to enable using a different PKI
         implementation.

      .. option:: ca.service.address = <string>

         Address of the CA Service that handles the delegated certificate renewal requests.

      .. option:: ca.service.shared_secret = <string>

	      Path to the PEM-encoded shared secret that is used to create JWT tokens.

      .. option:: ca.service.lifetime = <duration> (Default: "10m")

         Validity period (a :ref:`duration <control-conf-duration>`) of JWT authorization tokens
         for the CA service.

      .. option:: ca.service.client_id = <string> (Default: general.id)

         Client identifier for the CA service.
         Defaults to :option:`general.id <control-conf-toml general.id>`.


.. option:: trust_db (Required)

   :ref:`Database connection configuration <common-conf-toml-db>`
   for :term:`Control-Plane PKI` information.

   This database file contains cached certificate data.
   If it is destroyed, the control service will fetch required certificate information from
   authoritative ASes on-demand.

.. option:: beacon_db (Required)

   :ref:`Database connection configuration <common-conf-toml-db>`
   for received :term:`Path-Construction Beacon`\s.

   This database holds beacons that may be candidates for propagation.
   If it is destroyed, the control service may temporarily not have beacons to propagate to
   downstream neighbor ASes, until fresh PCBs are received from upstream neighbor ASes.

.. option:: path_db (Required)

   :ref:`Database connection configuration <common-conf-toml-db>`
   for Path Segment data.

   This database contains path segments, both explicitly registered segments as a result of the
   beaconing process, as well as cached results from path segment queries.
   If it is destroyed, the explicitly registered paths may be lost until
   they are rediscovered by the beaconing process. The path segments from cached path segment
   queries will be re-fetched on-demand.

.. _control-conf-topo:

topology.json
-------------

The :program:`control` reads the ``control_service`` section of the :ref:`topology.json <common-conf-topo>` file.

The entry referring to its own :option:`general.id <control-conf-toml general.id>`
define the addresses that :program:`control` will listen on.

The interface definitions in the ``border_router`` entries define the inter-AS links.
These entries define the beacons that :program:`control` will originate and propagate.

.. _control-conf-cppki:

Control-Plane PKI
-----------------

:program:`control` loads :term:`TRC`\s for the control-plane PKI from :option:`<config_dir>/certs <control-conf-toml general.config_dir>`.


.. _control-conf-keys:

Keys
----

:program:`control` loads the forwarding secret keys ``master0.key``/``master1.key`` from :option:`<config_dir>/keys <control-conf-toml general.config_dir>`.

The key files contain a base64-encoded high-entropy random string.
The keys should be exactly 16 bytes long (corresponding to a base64 encoding of 24 bytes with two trailing pad bytes ``==``).
These keys must be identical to the :ref:`corresponding keys used by the routers <router-conf-keys>`.

.. note::
   The :program:`router` and :doc:`control` currently use these keys as input for PBKDF2 to generate
   the actual forwarding key. Consequently, keys of any size can currently be used. This may be changed
   to only accept high-entropy 16 byte keys directly in the future.


.. _control-conf-duration:

Duration Format
---------------

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


Port table
==========

.. include:: ./control/port-table.rst

Metrics
=======

.. include:: ./control/metrics.rst

HTTP API
========

.. include:: ./control/http-api.rst
