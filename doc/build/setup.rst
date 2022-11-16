.. _setting-up-the-development-environment:

Setting up the development environment
======================================

Prerequisites
-------------

#. Make sure that you are using a clean and recently updated **Ubuntu 18.04**.
   Other Ubuntu versions (or systems) will usually be fine too, but some of the tooling may not work.
   This environment assumes you're running as a non-root user with ``sudo`` access.
#. Install ``docker``.
   Please follow the instructions for `docker-ce <https://docs.docker.com/install/linux/docker-ce/ubuntu/>`_.
   Then, add your user to the ``docker`` group:
   ``sudo usermod -a -G docker ${LOGNAME}``, where ``${LOGNAME}`` is replaced with your user name. Log out
   and log back in so that your membership of the ``docker`` group is seen by the shell session.

   Optionally install ``docker-compose``. This is needed if you want to run the
   ``docker-compose`` based test topology setup instead of the default setup based on ``supervisord``.
   Please follow the instructions for `docker-compose <https://docs.docker.com/compose/install/>`_.

Bazel & Co.
-----------

#. Clone the SCION repository into the appropriate directory inside your workspace. In the commands below,
   replace ``${WORKSPACE}`` with the directory in which you want to set up the project:

   .. code-block:: bash

      cd ${WORKSPACE}
      git clone https://github.com/scionproto/scion
      cd scion

#. We use `Bazel <https://bazel.build>`__ for both building and testing. To be
   able to define the bazel version in the repository we use the `bazelisk
   <https://github.com/bazelbuild/bazelisk>`__ wrapper around bazel. To set it
   up simply use::

      ./tools/install_bazel

   and make sure that ``~/bin`` is on your ``PATH``.

   You can also manually install ``bazelisk`` and create an alias so that
   ``bazel`` will resolve to the ``bazelisk`` command.

#. To install the required dependencies, run:

   .. code-block:: bash

      ./tools/install_deps

#. Start the bazel-remote container.

   We use `bazel-remote <https://github.com/buchgr/bazel-remote>`_ to cache
   build artifacts from bazel. Bazel-remote can manage the disk space and does
   not infinitely grow like the Bazel built-in disk-cache. To start bazel-remote run::

      ./scion.sh bazel_remote

#. Build SCION services and tools.

   .. code-block:: bash

      make

#. Finally, check that tests run correctly:

   .. code-block:: bash

      make test
      make test-integration

#. (Optional) If you already have some code you wish to contribute upstream, you can also run the
   linters locally with:

   .. code-block:: bash

      make lint


Alternative: go build
---------------------

Alternatively to building with bazel, the SCION services and tools can be built
with ``go build``.
Please be aware that **this is not the recommended setup for development**.
Not all checks and linters can be run in this setup. Without running all checks
locally, it is likely that there will be frustrating cycles with the CI system
rejecting your changes.

#. Determine the go version used in the bazel setup; the ``WORKSPACE`` file
   specifies this version in the ``go_register_toolchains`` clause.

   .. literalinclude:: ../../WORKSPACE
      :start-at: go_register_toolchains(
      :end-at: )
      :emphasize-lines: 3

   Building with newer go versions *usually* works.

#. Install go. Either follow `the official instructions <https://go.dev/doc/install>`_
   or check the `Ubuntu specific installation options on the golang wiki <https://github.com/golang/go/wiki/Ubuntu>`_.

#. Build SCION services and tools.

   .. code-block:: bash

      go build -o bin ./<service>/cmd/<service>...


Running SCION locally
---------------------

#. SCION networks are composed of many different applications. To simplify testing, we provide a
   tool that generates test topologies. To generate the files required by the default topology (see
   ``doc/fig/default_topo.png`` for a diagram of this topology), run:

   .. code-block:: bash

      ./scion.sh topology

   The above command creates the ``gen`` directory, which contains configuration files and cryptographic
   material for multiple SCION ASes and ISDs.

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


Wireshark
---------

To inspect SCION packets that are sent over the wire it can be helpful to use
Wireshark. We use version 3.x of Wireshark, which is not shipped by default on
Ubuntu 18.04. To install it use:

.. code-block:: bash

   sudo add-apt-repository ppa:wireshark-dev/stable
   sudo apt-get update
   sudo apt-get install wireshark

To use the SCION dissector you need to install it:

.. code-block:: bash

   mkdir -p ~/.wireshark/plugins
   cp tools/wireshark/scion.lua ~/.wireshark/plugins

After that you can test it by running a topology and using a SCION filter for
example::

    tshark -Y 'scion.dst_as == "ff00:0:110"'


Work remotely with Wireshark
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Sometimes it can be handy to use the remote feature of wireshark to tap into an
interface on a different machine.


#. Install wireshark on your local OS.

   - For Ubuntu install as described in the steps above.
   - For MacOS and Windows just download & install from the `wireshark website
     <https://www.wireshark.org/#download>`_.


#. Install dissector plugin

   To install the dissector lua plugin copy it in the plugin folder of wireshark:

   - Ubuntu:   same as in the previous step
   - Windows:  ``%APPDATA%\Wireshark\plugins``
   - MacOS:    ``/Applications/Wireshark.app/Contents/PlugIns/wireshark``

   .. note::
      The folder needs to be created if it doesn't exist.
      (for more details visit `wireshark website: Plugin folders
      <https://www.wireshark.org/docs/wsug_html_chunked/ChPluginFolders.html>`_)

#. Prepare the remote machine

   Install tcpdump::

      sudo apt-get install tcpdump

   The user used to SSH into the remote machine needs to have full access to tcpdump.
   Hence create a new group and add this user to the group. SSH into the remote machine
   and execute::

      sudo groupadd pcap
      sudo usermod -a -G pcap $USER

   set this group as the owner of tcpdump::

      sudo chgrp pcap /usr/sbin/tcpdump
      sudo chmod 750 /usr/sbin/tcpdump

   give tcpdump the necessary permissions::

      sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

   .. note::
      This will allow every user part of the pcap group to use the full
      capabilities of tcpdump!

#. Figure out the network interface on the remote host you want to tap into:
   Get an IP address used by the SCION topology that's probably running with docker.
   Search for the network-interface that's with the corresponding subnet.

#. Start wireshark and click on the gear next to the interface named
   "SSH remote capture: sshdump"
   Fill in the IP address and Port of the remote host, as well as your preferred
   authentication method in the Authentication tab.
   At the Capture tab write the name of the interface you found in the previous
   step. Find the a screenshot of an example below:

   .. image:: wireshark.png

#. Now you are ready to click start and investigate some SCION traffic

