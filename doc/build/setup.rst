.. _setting-up-the-development-environment:

Setting up the development environment
======================================

#. Make sure that you are using a clean and recently updated **Ubuntu 18.04**.
   This environment assumes you're running as a non-root user with ``sudo`` access.
#. We use `Bazel <https://bazel.build>`__ for both building and testing. To be
   able to define the bazel version in the repository we use the `bazelisk
   <https://github.com/bazelbuild/bazelisk>`__ wrapper around bazel. To set it
   up simply use::

      ./tools/install_bazel

   and make sure that ``~/bin`` is on your ``PATH``.

   You can also manually install ``bazelisk`` and create an alias so that
   ``bazel`` will resolve to the ``bazelisk`` command.

#. Next, clone the SCION repository into the appropriate directory inside your workspace. In the commands below,
   replace ``${WORKSPACE}`` with the directory in which you want to set up the project:

   .. code-block:: bash

      cd ${WORKSPACE}
      git clone https://github.com/scionproto/scion
      cd scion

#. For this step, make sure you are in the ``scion`` repository root. To install the required dependencies, run:

   .. code-block:: bash

      ./env/deps

#. Install ``docker``.
   Please follow the instructions for `docker-ce <https://docs.docker.com/install/linux/docker-ce/ubuntu/>`_.
   Then, add your user to the ``docker`` group:
   ``sudo usermod -a -G docker ${LOGNAME}``, where ``${LOGNAME}`` is replaced with your user name. Log out
   and log back in so that your membership of the ``docker`` group is seen by the shell session.

   Optionally install ``docker-compose``. This is needed if you want to run the
   ``docker-compose`` based test topology setup instead of the default setup based on ``supervisord``.
   Please follow the instructions for `docker-compose <https://docs.docker.com/compose/install/>`_.

#. Start the bazel-remote container.

   We use `bazel-remote <https://github.com/buchgr/bazel-remote>`_ to cache
   build artifacts from bazel. Bazel-remote can manage the disk space and does
   not infinitely grow like the Bazel built-in disk-cache. To start bazel-remote run::
   
      ./scion.sh bazel_remote

#. SCION networks are composed of many different applications. To simplify testing, we provide a
   tool that generates test topologies. To generate the files required by the default topology (see
   ``doc/fig/default_topo.png`` for a diagram of this topology), run:

   .. code-block:: bash

      ./scion.sh topology

   The above command creates the ``gen`` directory, which contains configuration files and cryptographic
   material for multiple SCION ASes and ISDs.
#. To start the infrastructure we just generated, run:

   .. code-block:: bash

      ./scion.sh run

#. To verify that your topology is running correctly, you can run an end to end reachability test using:

   .. code-block:: bash

      ./bin/end2end_integration

#. To stop the infrastructure, run:

   .. code-block:: bash

      ./scion.sh stop

#. Finally, check that unit tests run correctly:

   .. code-block:: bash

      ./scion.sh test

#. (Optional) If you already have some code you wish to contribute upstream, you can also run the
   linters locally with:

   .. code-block:: bash

      ./scion.sh lint

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
----------------------------
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

