******
Router
******

:program:`router` is the SCION router. Due to the encapsulation of SCION packets,
this can use ordinary UDP sockets for network communication and so can run
on almost any host system without requiring any special privileges.

.. TODO
   add reference to dataplane section


Command line reference
======================

To start the router, invoke :option:`router --config path/to/conf.toml <router --config>`.

.. program:: router

.. option:: --config <config.toml>

   Specify the configuration file.

   .. TODO

      Reference the configuration file

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


Configuration
=============

.. TODO

   This can probably be reused for control service etc.

The :program:`router` is configured two main files. First, the :ref:`.toml <router-conf-toml>` configures
features like logging and metrics and specifies the **configuration directory** from which
all other configuration files are read. The second one is ``topology.json``, which contains all
the AS information that the router uses to forward packets.

.. _router-conf-toml:

Main router configuration .toml
-------------------------------

The main router configuration is a `TOML <https://toml.io/en/>`_-file.

The following keys are defined. Specifying any undefined options results in an error at startup of
the program (to avoid silently ignoring any accidental misspellings of options).

.. program:: router-conf-toml

.. option:: general.config_dir = <string> (Required)

   Path to a directory for loading AS :ref:`topology.json <router-conf-topo>` and :ref:`keys <router-conf-keys>`.

   :program:`router` will search auxiliary configuration files in this directory.

   If this is a relative path, it is interpreted as relative to the current working directory of the
   program (i.e. **not** relative to the location of this .toml configuration file).

.. option:: general.id = <string> (Required)

   Identifier for this router.

   This is used to identify which parts of the :ref:`router-conf-topo` file refer to self.
   Thus, this ``id`` must match a key in the :ref:`router-conf-topo` files' ``border_routers`` section.

.. option:: log.console.level = "debug"|"info"|"error" (Default: "info")

   Log level at startup.

   The log level can be changed at runtime via the :ref:`HTTP API <common-http-api>`.

.. option:: log.console.format = "human"|"json" (Default: "human")

   Encode the log either in a human oriented form or json.

.. option:: log.console.disable_caller = <boolean>

   If ``true``, disable annotating logs with the calling function's file name and line number.
   By default, all logs are annotated.

.. option:: metrics.prometheus = <string>

   Address on which to export the :ref:`common HTTP API <common-http-api>`, in the form
   ``host:port``, ``ip:port`` or ``:port``.
   The eponymous prometheus metrics can be found under ``/metrics``, but other endpoints
   are always exposed as well.

   If not set, the HTTP API is not enabled.

.. _router-conf-topo:

topology.json
-------------


The :program:`router` reads the ``border_routers`` section of the ``topology.json`` file.


It uses the entry referring to its own ``general.id`` to determine the intra-AS links
that this router instance is responsible for.
The other router entries ("sibling routers") define which router is responsible for which
interface. This mapping is consulted during forwarding to determine the ``internal_addr`` of the
sibling router that an packet transitting the AS needs to forwarded to.

..
   Note: use YAML syntax highlighting for JSON because this allows annotation comments and
   accidentally gives pretty nice coloring for placeholders.
   TODO generalize the topology file documentation and reference this from here.

.. code-block:: yaml

   {
      "border_routers": {
         <router-id>: {                     # router-id matches the general.id of a router
            "internal_addr": <ip:port>,
            "interfaces": {
               <interface-id>: {            # interface-id is a number in a string, e.g. "42"
                  "isd_as": <neighbor-isd-as>,
                  "link_to": <"parent"|"child"|"peer">,
                  "mtu": <link-mtu>,
                  "underlay": {
                     "public": <ip:port>,
                     "bind": <ip>,          # optional; locally bind on this instead of public.ip
                     "remote": <ip:port>,
                  },
               }
               # ... more interfaces ...
            }
         }
         # ... more routers ...
      }
   }



.. _router-conf-keys:

Keys
----

The :program:`router` loads the forwarding secret keys ``master0.key``/``master1.key`` from :option:`<config_dir>/keys <router-conf-toml general.config_dir>`.

The key files contain a base64-encoded high-entropy random string.
The keys should be exactly 16 bytes long (corresponding to a base64 encoding of 24 bytes with two trailing pad bytes ``==``).
These keys must be identical to the corresponding keys used by the :doc:`control`.

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
