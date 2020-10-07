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

   We use `bazel-remote <https://github.com/buchgr/bazel-remote>`_ to chache
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
