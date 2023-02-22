*********************
Running SCION locally
*********************

SCION is an internet architecture and SCION networks are composed of
many hosts running the SCION control-plane services, routers and SCION-enabled
applications.
To simplify development, testing and tinkering, we provide a tool that generates test
topologies and runs an entire SCION "internet" on a single machine. Packets are
only sent between different processes on the same host, not over the network.

Running SCION in this developement setup, is also called running a **local topology**.

The scripts support two different process orchestrators as "backends":

- `supervisor <http://supervisord.org/>`_. This is the default and a bit more light-weight. Packets are sent over the loopback interface.
- `docker-compose <https://docs.docker.com/compose/>`_. Runs individual processes in separate containers connected with docker network bridges. Only this mode supports running a "SCION-IP gateway".

..
   - This document is :
     - Tutorial (quickstart)
     - Explanation (what is this, how does it relate to SCION)
     - (shallow) reference manual for tools

.. TODO

   - Describe configuration directory (referencing manuals)
   - How to use

Quickstart
==========

.. admonition:: Prerequisites

   * :doc:`setup`

   * Build, using ``make``

#. Generate the control-plane PKI keys and certificates, configuration files and process orchestrator (supervisor or docker-compose) configuration.

   .. code-block:: bash

      ./scion.sh topology -c topology/tiny.topo


   .. Attention:: The certificates created by this command expire after 3 days if the
      infrastructure is not running for automatic renewal.

#. To start the infrastructure we just generated, run:

   .. code-block:: bash

      ./scion.sh run

#. To verify that your topology is running correctly, you can run an end to end reachability test using:

   .. code-block:: bash

      ./bin/end2end_integration

#. This local infrastructure runs multiple SCION daemons, one in each AS.
   We need to specify which instance is used when running end-host applications
   that rely on the SCION daemon, e.g. to query paths.

   The ``scion.sh topology`` script writes a file ``gen/sciond_address.json``,
   mapping AS numbers to SCION daemon instance addresses. Either consult this
   file manually, or use the ``scion.sh sciond-addr`` command:

   .. code-block:: bash

      # show paths from 1-ff00:0:112 to 1-ff00:0:110
      ./bin/scion showpaths --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110


#. To stop the infrastructure, run:

   .. code-block:: bash

      ./scion.sh stop


scion.sh
========

:program:`scion.sh` is the developer script to setup and run a local topology.

.. Note::
   The SCION tools and services need to be built **before** running these commands, using
   ``make`` or ``make docker-images`` (when using the docker-compose configuration).

The basic usage is ``./scion.sh <subcommand> <options>``. The main subcommands are:

.. object:: topology

   Generate the control-plane PKI keys and certificates, configuration files
   and process orchestrator (supervisor or docker-compose) configuration.

   .. option:: -c <FILE.topo>, --topo-config <FILE.topo>

      Path to the :file-ref:`*.topo configuration file <topology/README.md>`.

   .. option:: -d, --docker

      Create a docker-compose configuration (instead of default supervisord).

   .. option:: --sig

      Generate a :doc:`/manuals/gateway` for each AS.
      Only available with -d.

   .. option:: -h, --help

      Display help text, list all options

.. describe:: help

   Describe all available subcommands


