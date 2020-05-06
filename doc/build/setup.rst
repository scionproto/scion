.. _setting-up-the-development-environment:

Setting up the development environment
======================================

#. Make sure that you are using a clean and recently updated **Ubuntu 18.04**.
   This environment assumes you're running as a non-root user with ``sudo`` access.
#. We use `Bazel <https://bazel.build>`__ for both building and testing. To set up the
   development environment, please install Bazel version 1.2.0:

   .. code-block:: bash

      sudo apt-get install g++ unzip zip
      wget https://github.com/bazelbuild/bazel/releases/download/1.2.0/bazel-1.2.0-installer-linux-x86_64.sh
      bash ./bazel-1.2.0-installer-linux-x86_64.sh --user
      rm ./bazel-1.2.0-installer-linux-x86_64.sh

#. Next, clone the SCION repository into the appropriate directory inside your workspace. In the commands below,
   replace ``${WORKSPACE}`` with the directory in which you want to set up the project:

   .. code-block:: bash

      cd ${WORKSPACE}
      git clone https://github.com/scionproto/scion
      cd scion

#. For this step, make sure you are in the ``scion`` repository root. To install the required dependencies, run:

   .. code-block:: bash

      ./env/deps

#. (Optional) If you want to run applications via docker, install ``docker`` and ``docker-compose``.
   Please follow the instructions for `docker-ce <https://docs.docker.com/install/linux/docker-ce/ubuntu/>` and
   `docker-compose <https://docs.docker.com/compose/install/>`. Then, add your user to the ``docker`` group:
   ``sudo usermod -a -G docker ${LOGNAME}``, where ``${LOGNAME}`` is replaced with your user name. Log out
   and log back in so that your membership of the ``docker`` group is seen by the shell session.
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
