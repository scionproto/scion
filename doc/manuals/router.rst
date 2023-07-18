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

Environment Variables
---------------------

.. envvar:: SCION_EXPERIMENTAL_BFD_DISABLE

   Disable :term:`BFD`, unconditionally consider the connection alive.

   Applies to BFD sessions to all sibling routers (other routers in the same AS).
   Can be overridden for specific inter-AS BFD sessions with :option:`bfd.disable <topology-json disable>`
   in an interface entry in the ``topology.json`` configuration.

.. envvar:: SCION_EXPERIMENTAL_BFD_DETECT_MULT

   Set the :term:`BFD` detection time multiplier.

   Default 3

   Same applicability as above; can be overridden for specific inter-AS BFD sessions with
   :option:`bfd.detect_mult <topology-json detect_mult>`.

.. envvar:: SCION_EXPERIMENTAL_BFD_DESIRED_MIN_TX

   Defines the frequence at which this router should send :term:`BFD` control messages.

   Default 200ms

   Same applicability as above; can be overridden for specific inter-AS BFD sessions with
   :option:`bfd.desired_min_tx_interval <topology-json desired_min_tx_interval>`.

.. envvar:: SCION_EXPERIMENTAL_BFD_REQUIRED_MIN_RX

   Defines an frequence at which this router should send :term:`BFD` control messages.

   Default 200ms

   Same applicability as above; can be overridden for specific inter-AS BFD sessions with
   :option:`bfd.required_min_rx_interval <topology-json required_min_rx_interval>`.

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
