*********************
Running SCION Locally
*********************

SCION is an Internet architecture and SCION networks are composed of
many hosts running the SCION control-plane services, routers, and SCION-enabled
applications.
To simplify development, testing, and tinkering, we provide a tool that generates test
topologies and runs an entire SCION "Internet" on a single machine. Packets are
only sent between different processes on the same host, not over the network.

Running SCION in this developement setup, is also called running a **local topology**.

The scripts support two different process orchestrators as "backends":

- `supervisor <http://supervisord.org/>`_. This is the default and a bit more light-weight. Packets are sent over the loopback interface.
- `docker compose <https://docs.docker.com/compose/>`_. Runs individual processes in separate containers connected with docker network bridges. Only this mode supports running a "SCION-IP gateway".

  .. hint:: Before attempting to use the docker compose mode, be sure to build the necessary docker images with ``make docker-images``

.. TODO
   - Describe configuration directory (referencing manuals)
   - How to use

Quickstart
==========

.. admonition:: Prerequisites

   * :doc:`setup`

   * Build, using ``make``

#. Generate the control-plane PKI keys and certificates, configuration files, and process
   orchestrator (supervisor or docker compose) configuration.

   .. code-block:: bash

      ./scion.sh topology -c topology/tiny.topo


   .. Attention:: The certificates created by this command expire after 3 days if the
      infrastructure is not running for automatic renewal.

#. To start the infrastructure we just generated, run:

   .. code-block:: bash

      ./scion.sh run

#. To verify that your topology is running correctly, you can run an end to end reachability test using:

   .. code-block:: bash

      bin/end2end_integration

#. This local infrastructure runs multiple SCION daemons, one in each AS.
   We need to specify which instance is used when running applications
   that rely on the SCION daemon, e.g. to query paths.

   .. code-block:: bash

      # show paths from 1-ff00:0:112 to 1-ff00:0:110
      bin/scion showpaths --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110


#. To stop the infrastructure, run:

   .. code-block:: bash

      ./scion.sh stop

Local Topology Environment
==========================

The :option:`scion.sh topology` command generates configuration in the ``gen/`` directory in the
repository.

There is a subdirectory for each AS (e.g. ``gen/ASff00_0_110`` for AS ``ff00:0:110``), containing
the configuration for the services and routers of that AS.
Specifically, these contain the :ref:`.toml <common-conf-toml>` configuration files for the individual
components and a shared :ref:`topology.json <common-conf-topo>` configuration.

Various helper files are also generated for the benefit of scripts and tooling of the test infrastructure,
for example, ``gen/sciond_addresses.json`` is a simple mapping from AS number to the address of the
corresponding :doc:`scion daemon </manuals/daemon>` instance.

If  :option:`scion.sh topology -d` command is used, configuration files are created to
enable running the SCION services in docker containers (see :ref:`docker-section`). Otherwise,
a configuration file is created to enable running the SCION services as plain processes
(see :ref:`supervisor-section`)

.. _supervisor-section:

supervisor
----------
The ``gen/supervisord.conf`` configuration defines the programs that make up the local topology.

All the SCION traffic goes via the loopback interface, the separation of the internal
networks of the simulated ASes is not enforced in any way.

There is a single :doc:`/manuals/dispatcher` instance, receiving and sending the SCION packets for
the :doc:`/manuals/control` instances and SCION applications/tools in all simulated ASes.

There is one :doc:`/manuals/daemon` instance running for each simulated AS.
Commands accessing the SCION network can be run directly from the host. The information about the
local AS in which the command is running, is determined by the SCION daemon instance that the
command connects to.
For example::

   # show paths from 1-ff00:0:112 to 1-ff00:0:110
   bin/scion showpaths --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110

   # reveal the full SCION address of a simulated host in in 1-ff00:0:111
   bin/scion address --sciond $(./scion.sh sciond-addr 111)

   # and now ping this host from inside AS 1-ff00:0:110, with interactive path prompt
   bin/scion ping --sciond $(./scion.sh sciond-addr 110) 1-ff00:0:111,127.0.0.1 --interactive

.. _docker-section:

docker
------
The main docker compose file is ``gen/scion-dc.yml``.

Each SCION service or router runs in a separate container, and the network access of the individual
containers is configured to mimick real-world connectivity.

There are "tester" containers configured in each AS to mimick end hosts in a SCION AS.
These tester containers can be used to run commands accessing the SCION network.
As a shorthand for the somewhat unwieldy ``docker compose`` invocation, the :file-ref:`tools/dc`
script can be used. For example::

   # show paths from 1-ff00:0:112 to 1-ff00:0:110
   tools/dc exec_tester 1-ff00_0_112 bin/scion showpaths 1-ff00:0:110

   # reveal the full SCION address of the tester container in 1-ff00:0:111
   tools/dc exec_tester 1-ff00_0_111 bin/scion address

   # and now ping this host from inside AS 1-ff00:0:110, with interactive path prompt
   tools/dc exec_tester 1-ff00_0_110 bin/scion ping 1-ff00:0:111,172.20.0.29

Note that the ``--sciond`` flag does not need to be provided in this setup, as it's preconfigured
in the tester containers via the environment variable ``SCION_DAEMON``.

scion.sh
========

:program:`scion.sh` is the developer script to setup and run a local topology.

.. Note::
   The SCION tools and services need to be built **before** running these commands, using
   ``make`` or ``make docker-images`` (when using the docker compose configuration).

The basic usage is ``./scion.sh <subcommand> <options>``. The main subcommands are:

.. program:: scion.sh

.. option:: topology

   Generate the control-plane PKI keys and certificates, configuration files,
   and process orchestrator (supervisor or docker compose) configuration
   for a given network topopology defined in a
   :file-ref:`*.topo configuration file <topology/README.md>`.

   .. program:: scion.sh topology

   .. option:: -c <FILE.topo>, --topo-config <FILE.topo>

      Path to the :file-ref:`*.topo configuration file <topology/README.md>`.

   .. option:: -d, --docker

      Create a docker compose configuration (instead of default supervisord).

   .. option:: --sig

      Generate a :doc:`/manuals/gateway` for each AS.
      Only available with -d.

   .. option:: -h, --help

      Display help text, list all options

.. option:: run, start

   Start the local SCION topology.

.. option:: stop

   Terminate this run of the local SCION topology.

.. option:: start-monitoring

   Start the monitoring services (jaeger and prometheus).

.. option:: stop-monitoring

   Stop the monitoring services.

.. option:: sciond-addr <ISD-AS>

   Return the address for the scion daemon for the matching ISD-AS by consulting
   ``gen/sciond_addresses.json``.
   The ISD-AS parameter can be a substring of the full ISD-AS (e.g. last three digits), as long as
   there is a unique match.

.. option:: help

   Describe all available subcommands

end2end_integration
===================

:program:`bin/end2end_integration` is a basic functional test.

The basic usage is ``./end2end_integration <options>``.

.. program:: end2end_integration

.. option:: -d

   Assume the SCION services are dockerized. Must be consistent with the last
   invocation of ``scion.sh topology``.
