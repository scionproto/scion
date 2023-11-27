.. _setting-up-the-development-environment:

Setting up the Development Environment
======================================

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

Bazel
-----

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

  .. hint:: This installs tools for tests in addition to the main SCION services (e.g., `end2end`);
     if you don't require those, you can only build the SCION services by running ``make build``.

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

   .. literalinclude:: /../WORKSPACE
      :start-at: go_register_toolchains(
      :end-at: )
      :emphasize-lines: 3

   Building with newer go versions *usually* works.

#. Install go. Either follow `the official instructions <https://go.dev/doc/install>`_
   or check the `Ubuntu specific installation options on the golang wiki <https://github.com/golang/go/wiki/Ubuntu>`_.

#. Decide which implementation of sqlite you want to use:

   - `mattn`: A cgo implementation. It is well established but makes go
     executables dependent on a minimum glibc version.
   - `modernc`: A pure go implementation. It does not cause glibc version
     issues but is less common. modernc is currently recommended due to
     the glibc issue.

#. Build SCION services and tools.

   .. code-block:: bash

      go build -o -tags sqlite_<impl> bin ./<service>/cmd/<service>...

   where <impl> is one of `modernc` or `mattn`.


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
