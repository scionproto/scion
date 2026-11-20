*********************
Running SCION Locally
*********************

SCION is an Internet architecture and SCION networks are composed of
many hosts running the SCION control-plane services, routers, and SCION-enabled
applications.
To simplify development, testing, and tinkering, we provide a tool that generates test
topologies and runs an entire SCION "Internet" on a single machine. Packets are
only sent between different processes on the same host, not over the network.

Running SCION in this development setup, is also called running a **local topology**.

There are three different ways to run a local topology:

- `containerlab <https://containerlab.dev/>`_ (**recommended**). Each SCION host runs in its own
  container. The inter-AS links are dedicated point-to-point links between the containers, so the
  network closely mimics real-world connectivity. See :ref:`containerlab-section`.
- `supervisor <http://supervisord.org/>`_, using :program:`scion.sh`. This is a bit more
  light-weight. Packets are sent over the loopback interface.
- `docker compose <https://docs.docker.com/compose/>`_, using :program:`scion.sh`. Runs individual
  processes in separate containers connected with docker network bridges. Only this mode supports
  running a "SCION-IP gateway".

  .. hint:: Before attempting to use the docker compose mode, be sure to build the necessary docker images with ``make docker-images``

.. TODO
   - Describe configuration directory (referencing manuals)
   - How to use

Quickstart
==========

.. admonition:: Prerequisites

   * :doc:`setup`, including the containerlab CLI (``clab``).

#. Build the SCION node image and load it into docker. It contains the SCION services, the
   ``scion`` CLI and the test applications.

   .. code-block:: bash

      bazel run //testing/clab:clab_node.load

   Re-run this whenever you change the code, so that the next deployment picks up the changes.

#. Generate the control-plane PKI keys and certificates, configuration files, and the
   containerlab topology ``gen/scion.clab.yml``:

   .. code-block:: bash

      bazel run --run_in_cwd //testing/clab/cmd/testgen -- --topo topology/tiny.topo

   See :ref:`testgen-section` for the available options.

   .. Attention:: This deletes the existing ``gen/`` directory. The certificates created by this
      command expire after 365 days if the infrastructure is not running for automatic renewal.

#. Deploy the topology:

   .. code-block:: bash

      clab deploy -t gen/scion.clab.yml

   If a lab of the same name is already running, add ``--reconfigure`` to replace it.

#. Wait until the control services have beaconed and all ASes can reach each other:

   .. code-block:: bash

      bazel run --run_in_cwd //testing/clab/cmd/await_connectivity

#. To verify that your topology is running correctly, you can run the end to end tests.
   ``e2e_scion`` runs ``scion ping`` and ``scion showpaths`` between all pairs of ASes,
   ``e2e_http`` runs an HTTP/3 server in each AS and fetches from it from all other ASes:

   .. code-block:: bash

      bazel run --run_in_cwd //testing/clab/cmd/e2e_scion
      bazel run --run_in_cwd //testing/clab/cmd/e2e_http run

#. This local infrastructure runs one SCION daemon per AS. We need to specify which instance is
   used when running applications that rely on the SCION daemon, e.g. to query paths.
   The daemons are reachable from the machine running the lab:

   .. code-block:: bash

      # show paths from 1-ff00:0:112 to 1-ff00:0:110
      bazel run //scion/cmd/scion -- showpaths --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110

#. To stop the infrastructure, run:

   .. code-block:: bash

      clab destroy -t gen/scion.clab.yml --cleanup

Quickstart with scion.sh
------------------------

.. admonition:: Prerequisites

   * :doc:`setup`

   * Build, using ``make``

#. Generate the control-plane PKI keys and certificates, configuration files, and process
   orchestrator (supervisor or docker compose) configuration.

   .. code-block:: bash

      ./scion.sh topology -c topology/tiny.topo


   .. Attention:: The certificates created by this command expire after 365 days if the
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

.. _containerlab-section:

containerlab
------------
The topology is generated by :ref:`testgen <testgen-section>` into the ``gen/`` directory:

- ``gen/scion.clab.yml`` is the containerlab topology.
- There is a subdirectory for each AS (e.g. ``gen/ASff00_0_110`` for AS ``ff00:0:110``), with the
  AS's crypto material, the shared :ref:`topology.json <common-conf-topo>`, and a subdirectory per
  host (e.g. ``gen/ASff00_0_110/host-1``) that is mounted into that host's container.
- ``gen/sciond_addresses.json`` maps each AS to the address of its
  :doc:`scion daemon </manuals/daemon>`.
- ``gen/network-allocations.yml`` lists the subnets and addresses assigned to the ASes, the hosts
  and the links.

Each SCION host is a container named ``clab-<lab>-<ISD-AS>-host-<N>``, e.g.
``clab-scion-1-ff00_0_110-host-1``. Every AS has at least ``host-1``, which runs the
:doc:`/manuals/control` and the :doc:`/manuals/daemon` of the AS, and a :doc:`/manuals/router`.
Additional border routers of the AS run on additional hosts.
Inside the container, a controller process starts the SCION services according to the mounted
configuration.

All hosts are attached to the containerlab management network, which also serves as the internal
network of each AS. The inter-AS links are point-to-point links between the containers.

Commands accessing the SCION network can be run inside the containers. The SCION binaries are
located in ``/app``. For example::

   # show paths from 1-ff00:0:112 to 1-ff00:0:110
   docker exec clab-scion-1-ff00_0_112-host-1 /app/scion showpaths \
      --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110

They can also be run directly on the machine running the lab, as it is attached to the management
network. The local AS is determined by the SCION daemon instance that the command connects to::

   # show paths from 1-ff00:0:112 to 1-ff00:0:110
   bazel run //scion/cmd/scion -- showpaths --sciond $(./scion.sh sciond-addr 112) 1-ff00:0:110

By default, an application running on the machine uses the machine's address on the management
network. To give the machine a dedicated address in each AS, e.g. to run a server there, generate
the topology with :option:`testgen --host-links`. The addresses are listed under ``host_links`` in
``gen/network-allocations.yml``. For example, to run an HTTP/3 server on the machine in
``1-ff00:0:112`` and fetch from it on the machine in ``1-ff00:0:110``::

   bazel run //testing/clab/cmd/e2e_http -- server \
      --sciond $(./scion.sh sciond-addr 112) --listen <host_addr of 1-ff00:0:112>:31000

   bazel run //testing/clab/cmd/e2e_http -- client \
      --sciond $(./scion.sh sciond-addr 110) --remote '1-ff00:0:112,<host_addr of 1-ff00:0:112>:31000'

IPv6 addresses must be enclosed in brackets, e.g. ``[fd00:f00d:cafe:9000::2]:31000``.

scion.sh (supervisor and docker compose)
----------------------------------------

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
^^^^^^^^^^
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
^^^^^^
The main docker compose file is ``gen/scion-dc.yml``.

Each SCION service or router runs in a separate container, and the network access of the individual
containers is configured to mimic real-world connectivity.

There are "tester" containers configured in each AS to mimic end hosts in a SCION AS.
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

.. _testgen-section:

testgen
=======

:program:`testgen` generates a containerlab topology from a
:file-ref:`*.topo configuration file <topology/README.md>`. Run it from the repository root with::

   bazel run --run_in_cwd //testing/clab/cmd/testgen -- <options>

.. program:: testgen

.. option:: --topo <FILE.topo>

   Path to the :file-ref:`*.topo configuration file <topology/README.md>`.
   Default: ``topology/default.topo``.

.. option:: -o <DIR>, --out <DIR>

   Output directory. It is deleted before generating. Default: ``gen``.

.. option:: --name <NAME>

   Name of the containerlab lab. It is part of the container names and of the topology file name
   (``gen/<NAME>.clab.yml``). Default: ``scion``.

.. option:: --network <PREFIX>, --network-v6 <PREFIX>

   Base IPv4 and IPv6 networks from which the AS-internal networks and the link networks are
   allocated. Defaults: ``10.0.0.0/8`` and ``fd00:f00d:cafe::/48``. They must not overlap with any
   other network on the machine.

.. option:: --host-links

   Connect ``host-1`` of every AS to the machine running the lab with a dedicated link. This gives
   the machine an address in each AS, which applications running on the machine can bind to.

.. option:: --gateways

   Run a :doc:`/manuals/gateway` on ``host-1`` of every AS. Each gateway owns an IPv4 ``/24``
   prefix and holds its first address on the loopback interface of the host. The gateways route
   the prefixes of all other ASes through their tunnels. The prefixes are recorded in
   ``network-allocations.yml``.

.. option:: --gateway-network <PREFIX>

   IPv4 network from which the gateway prefixes are allocated, one ``/24`` per AS. Default:
   ``172.16.0.0/16``. It must not overlap with the base IPv4 network, nor with the default
   networks of docker (``172.17.0.0/16``) and containerlab (``172.20.20.0/24``).

.. option:: --isd-dir

   Group the AS directories in per-ISD directories.

.. option:: --as-validity <DURATION>

   Validity of the generated AS certificates. Default: ``1y``.

The whole lifecycle (generate, deploy, run the end to end tests, destroy) is also available as a
bazel test::

   bazel test //testing/clab/system_test:go_default_test --test_output=streamed

The system tests are defined with the ``clab_system_test`` macro from
``//testing/clab:system_test.bzl``. Besides the test itself, it creates a target for each phase of
the test, so that the lab can be set up once and the tests run against it repeatedly. The lab
stays deployed between the phases::

   bazel run //testing/clab/system_test:go_default_test_setup
   bazel run //testing/clab/system_test:go_default_test_run
   bazel run //testing/clab/system_test:go_default_test_teardown

The SCION IP gateways are tested in the same way, in a lab generated with
:option:`testgen --gateways`. The test pings through the gateways for each combination of RPC
protocols of the control services and gateways::

   bazel test //gateway/system_test:go_default_test --test_output=streamed

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
   for a given network topology defined in a
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
