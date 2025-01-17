.. _setting-up-the-development-environment:

Setting up the Development Environment
======================================

.. hint::

   These instructions describe the setup for building and running all integration tests with bazel,
   docker and various other tools and scripts.
   See :doc:`build` for instructions focussing only on how to build the SCION executables.

macOS (Apple silicon) Prerequisites
-----------------------------------

.. hint::

   If you're not developing on a Mac, please skip this section and
   go straight to :ref:`linux_prerequisites`.

.. Warning::

   Currently, ARM64 isn't an officially supported development platform, and you may
   face unresolved issues, particularly when executing integration tests.
   Running Lima in QEMU x86_64 emulation will work, but is too slow for practical use.

To set up a development environment on a macOS 13 (or above) M-series Apple silicon macbook
you'll need to set up a Linux virtual machine.
We recommend you use `Lima <https://github.com/lima-vm/lima>`_ by following the instructions below.

#. Install Lima VM:

   .. code-block:: bash

      brew install lima

#. Create the shared workspace directory:

   .. code-block:: bash

      mkdir /Users/$USER/limavm

   .. hint::

      Use this workspace directory to host the ``scion`` repository.
      By default, Lima mounts your home directory in read-only mode (recommended)
      but this will cause issues when using ``make``.

#. Configure the ``default`` Lima VM:

   .. code-block:: bash

      limactl start

   If the above command opens an interactive prompt, select
   ``Open an editor to review or modify the current configuration``,
   otherwise manually edit ``~/.lima/default/lima.yaml``.

   Change the following fields in your ``default`` VM configs.

   .. code-block:: yaml

      vmType: "vz"

   .. code-block:: yaml

      arch: "aarch64"

   Add a shared read-write mount that will serve as the main workspace:

   .. code-block:: yaml

      - location: /Users/{{.User}}/limavm   # macOS directory
        writable: true                      # Writable for the VM
        mountPoint: /home/{{.User}}/shared  # Directory inside the VM

   Optionally, adjust ``cpus``, ``memory`` and ``disk`` as you see fit.

#. Start the ``default`` VM:

   .. code-block:: bash

      limactl start default

#. SSH into the VM:

   .. code-block:: bash

      lima

#. Navigate to the workspace:

   .. code-block:: bash

      cd /home/$USER/shared

   Now you're ready to continue with :ref:`linux_prerequisites` to setup the Linux system running
   within the Lima virtual machine.

.. _linux_prerequisites:

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

   .. Warning::

      Integration tests will fail to execute on ARM64 due to OpenWRT.
      The current workaround is to remove the ``"integration"`` tag from
      ``"openwrt_test"`` in ``dist/test/BUILD.bazel``.

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
