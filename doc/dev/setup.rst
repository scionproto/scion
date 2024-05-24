.. _setting-up-the-development-environment:

Setting up the Development Environment
======================================

.. hint::

   These instructions describe the setup for building and running all integration tests with bazel,
   docker and various other tools and scripts.
   See :doc:`build` for instructions focussing only on how to build the SCION executables.

Prerequisites
-------------

#. Make sure that you are using a clean and recently updated linux distribution. Distributions that are
   known to work are:

   - **Ubuntu** release 18.04 or later.
   - **Fedora** release 38 or later.
   - **Amazon** Linux 2.

   Other Linux environments will usually be fine too, but some of the tooling might need
   tweaking. If you make things work for other distributions, please update this list.

   This environment assumes you're running as a non-root user with ``sudo`` access.
#. Install ``docker``.
   Please follow the instructions for `docker server <https://docs.docker.com/engine/install/#server>`_.
   Then, add your user to the ``docker`` group:
   ``sudo usermod -a -G docker ${LOGNAME}``, where ``${LOGNAME}`` is replaced with your user name. Log out
   and log back in so that your membership of the ``docker`` group is seen by the shell session.

   Optionally install the ``Docker Compose Plugin``. This is needed if you want to run the
   ``docker compose`` based test topology setup instead of the default setup based on ``supervisord``.
   Please follow the instructions for
   `Install Compose Plugin <https://docs.docker.com/compose/install/linux/#install-using-the-repository>`_.

Setup
-----

#. Clone the SCION repository into your workspace.

   .. code-block:: bash

      git clone https://github.com/scionproto/scion
      cd scion

#. We use `Bazel <https://bazel.build>`__ for both building and testing. To be
   able to define the bazel version in the repository we use the `bazelisk
   <https://github.com/bazelbuild/bazelisk>`__ wrapper around bazel. To set it
   up simply use::

      ./tools/install_bazel

   and make sure that ``~/.local/bin`` is on your ``PATH``.

   You can also manually install ``bazelisk`` and create an alias so that
   ``bazel`` will resolve to the ``bazelisk`` command.

#. To install the required build toolchains and scripting dependencies, run:

   .. code-block:: bash

      ./tools/install_deps

#. Start the bazel-remote container.

   We use `bazel-remote <https://github.com/buchgr/bazel-remote>`_ to cache
   build artifacts from bazel. Bazel-remote can manage the disk space and does
   not infinitely grow like the Bazel built-in disk-cache. To start bazel-remote run::

      ./scion.sh bazel-remote

#. Build SCION services and tools.

   .. code-block:: bash

      make

   .. hint:: This builds tools for tests in addition to the main SCION services (e.g., ``end2end``);
      if you don't require those, you can only build the SCION services by running ``make build``.
      See :doc:`build` for more details.

#. Finally, check that tests run correctly:

   .. code-block:: bash

      make test
      make test-integration

#. (Optional) If you already have some code you wish to contribute upstream, you can also run the
   linters locally with:

   .. code-block:: bash

      make lint


Tips and Tricks
---------------
.. toctree::
   :maxdepth: 1

   wireshark

.. seealso::
   :doc:`contribute`
      Learn :doc:`how to contribute <contribute>` to the SCION projects.

   :doc:`run`
      :doc:`Run a SCION network <run>` on your development machine.
