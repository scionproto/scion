******
Router
******

:program:`router` is the SCION router. Due to the encapsulation of SCION packets,
this can use ordinary UDP sockets for network communication and so can run
on almost any host system without requiring any special privileges.

.. TODO
   add reference to dataplane section

Command Line Reference
======================

.. program:: router

Synopsis
--------

:program:`router` [:option:`--config \<config.toml\> <router --config>` | :option:`help <router help>` | :option:`version <router version>`]

Options
-------

.. option:: --config <config.toml>

   Specifes the :ref:`configuration file <router-conf-toml>` and starts the router.

.. option:: help, -h, --help [subcommand]

   Display help text for subcommand.

.. option:: version

   Display version information.

.. option:: sample [file]

   Display sample files.

   .. option:: config

      Display a configuration file sample.

.. option:: completion [shell]

   Generate the autocompletion script for :program:`router` for the specified shell.

   Run :option:`router help completion <router help>` for a list of the available shells.

   Run :option:`router help completion [shell] <router help>` for usage information on the
   autocomplete script for a particular shell.

.. _router-envvars:

Environment Variables
---------------------

.. object:: SCION_TESTING_DRKEY_EPOCH_DURATION

   For **testing only**.
   This option relates :option:`features.experimental_scmp_authentication <router-conf-toml features.experimental_scmp_authentication>`.

   Override the global duration for :doc:`/cryptography/drkey` epochs.

   Also applies to the :ref:`control service <control-envvars>`.

   :Type: :ref:`duration <common-conf-duration>`
   :Default: ``24h``

.. envvar:: SCION_TESTING_ACCEPTANCE_WINDOW

   For **testing only**.
   This option relates :option:`features.experimental_scmp_authentication <router-conf-toml features.experimental_scmp_authentication>`.

   Defines the length of the window around the current time for which SCMP authentication timestamps
   are accepted. See :ref:`SPAO specification <spao-absTime>`.

   :Type: :ref:`duration <common-conf-duration>`
   :Default: ``5m``

.. envvar:: GOMAXPROCS

   Specified by the GO runtime. The Go runtime starts a number kernel threads such that the number
   of non-sleeping threads never exceeds ``GOMAXPROCS``. By default ``GOMAXPROCS`` is equal to the
   number of cores in the host. That value can be changed via the ``GOMAXPROCS`` environment
   variable (or programatically by the application code). See
   `the go runtime documentation <https://pkg.go.dev/runtime#hdr-Environment_Variables>`_
   for more information. One reason to change this is running multiple routers on the same host.
   In such a case, it is best to split the available cores among the routers, lest Go's default
   assumptions causes them to compete for cores and incurr futile context switching. This precaution
   is especially useful in performance testing situations.

   :Type: unsigned integer
   :Default: ``all cores``

Configuration
=============

The :program:`router` is configured by two main files.
First, the :ref:`.toml <router-conf-toml>` configures common features like logging and metrics and
specifies the **configuration directory** from which all other configuration files are read.
The second one is :ref:`topology.json <router-conf-topo>`, which contains all the AS information
that the router uses to forward packets.

.. _router-conf-toml:

Router Configuration
--------------------

In addition to the :ref:`common .toml configuration options <common-conf-toml>`, the router
considers the following options.

.. program:: router-conf-toml

.. object:: general

   .. option:: general.id = <string> (Required)

      Identifier for this router.

      This is used to identify which parts of the :ref:`router-conf-topo` file refer to self.
      Thus, ``id`` must match a key in the :ref:`router-conf-topo` files' ``border_routers`` section.

   .. option:: general.config_dir = <string> (Required)

      Path to a directory for loading AS :ref:`topology.json <router-conf-topo>` and :ref:`keys
      <router-conf-keys>`.

      If this is a relative path, it is interpreted as relative to the current working directory of the
      program (i.e. **not** relative to the location of this .toml configuration file).

.. object:: features

   Features is a container for generic, boolean feature flags (usually for experimental or
   transitional features).

   .. option:: features.experimental_scmp_authentication = <bool> (Default: false)

      Enable the :doc:`DRKey-based authentication of SCMPs </dev/design/scmp-authentication>` in the
      router, which is **experimental** and currently **incomplete**.

      When enabled, the router inserts the :ref:`authenticator-option` for SCMP messages.
      For now, the MAC is computed based on a dummy key, and consequently is not practically useful.

.. object:: router

   .. option:: router.receive_buffer_size = <int> (Default: 0)

      The receive buffer size in bytes. 0 means use system default.

   .. option:: router.send_buffer_size = <int> (Default: 0)

      The send buffer size in bytes. 0 means use system default.

   .. option:: router.num_processors = <int> (Default: GOMAXPROCS)

      Number of goroutines started for SCION packets processing.

      These goroutines make the routing decision for the SCION packets by inspecting, validating and
      updating the path information in the packet header. Packets are processed asynchronously from the
      corresponding read/write operations on the individual interface sockets.

      `Goroutines <https://en.wikipedia.org/wiki/Go_(programming_language)#Concurrency:_goroutines_and_channels>`_
      are the Go programming language's light-weight user-space concurrency primitives. Go's runtime
      schedules goroutines on top of a smaller number of kernel threads. The default is to use as
      many packet processors as there are kernel threads started by Go, letting other goroutines
      displace them sporadically. Whether more or fewer processors are preferable is to be determined
      experimentaly.

      The number of kernel threads that go creates depends on the number of usable cores, which is
      controlled by the environment variable ``GOMAXPROCS``. See :envvar:`GOMAXPROCS`.

   .. option:: router.num_slow_processors = <int> (Default: 1)

      Number of goroutines started for the slow-path processing which includes all SCMP traffic and
      traceroutes. A minimum of 1 slow-path processor is required.

   .. option:: router.batch_size = <int> (Default: 256)

      The batch size used by the receiver and forwarder to
      read or write from / to the network socket.

   .. object:: bfd

      .. option:: disable = <bool> (Default: false)

         Set whether the :term:`BFD` feature is disabled by default.

         This setting applies to BFD sessions to all neighboring routers, including sibling routers
         (other routers in the same AS).

         Can be overridden for specific inter-AS BFD
         sessions with :option:`bfd.disable <topology-json disable>`.

      .. option:: detect_mult = <uint8>, default 3

         Set the :term:`BFD` detection time multiplier.

         After ``detect_mult`` consecutively missing control packets, the BFD session is
         considered "down" and is reset.

         Can be overridden for specific inter-AS BFD sessions with
         :option:`bfd.detect_mult <topology-json detect_mult>`.

      .. option:: desired_min_tx_interval = <duration>, default 200ms

         Defines the frequency at which this router should send :term:`BFD` control messages.
         The effective interval is the result of negotiating with the remote router during
         session establishment;
         the value will be ``max(desired_min_tx_interval, remote.required_min_rx_interval)``.

         Can be overridden for specific inter-AS BFD sessions with
         :option:`bfd.desired_min_tx_interval <topology-json desired_min_tx_interval>`.

      .. option:: required_min_rx_interval = <duration>, default 200ms

         Defines an upper bound for the frequency at which this router wants to receive
         :term:`BFD` control messages.
         The effective interval at which the remote router will send control messages is the
         result of negotiating with the remote router during session establishment;
         the value will be ``max(remote.desired_min_tx_interval, required_min_rx_interval)``

         Can be overridden for specific inter-AS BFD sessions with
         :option:`bfd.required_min_rx_interval <topology-json required_min_rx_interval>`.

.. _router-conf-topo:

topology.json
-------------

The :program:`router` reads the ``border_routers`` section of the :ref:`topology.json <common-conf-topo>` file.

It uses the entry referring to its own :option:`general.id <router-conf-toml general.id>`
to determine the intra-AS links that this router instance is responsible for.
The other router entries ("sibling routers") define which router is responsible for which
interface. This mapping is consulted during packet forwarding to determine the
sibling router to which a packet transitting the AS needs to forwarded to.

Additionally, the :program:`router` considers the ``control_service`` and ``discovery_service``
entries. These entries define the underlay addresses that the router uses to resolves
anycast or multicast service addresses.

.. _router-conf-keys:

Keys
----

The :program:`router` loads the forwarding secret keys ``master0.key``/``master1.key`` from :option:`<config_dir>/keys <router-conf-toml general.config_dir>`.

The key files contain a base64-encoded high-entropy random string.
The keys should be exactly 16 bytes long (corresponding to a base64 encoding of 24 bytes with two trailing pad bytes ``==``).
These keys must be identical to the :ref:`corresponding keys used by the control service <control-conf-keys>`.

.. note::
   The :program:`router` and :doc:`control` currently use these keys as input for PBKDF2 to generate
   the actual forwarding key. Consequently, keys of any size can currently be used. This may be changed
   to only accept high-entropy 16 byte keys directly in the future.

Port table
==========

.. include:: ./router/port-table.rst

Metrics
=======

.. include:: ./router/metrics.rst

HTTP API
========

.. include:: ./router/http-api.rst
