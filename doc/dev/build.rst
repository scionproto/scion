********
Building
********

Building with go build
======================

SCION can be built with ``go build`` without any other system prerequisites.

Please be aware that go build **is not the recommended setup for development** on SCION.
Not all tests and checks can be run in this setup. We use Bazel to orchestrate all of this.
Without running all checks locally, it is likely that there will be frustrating cycles with the CI
system rejecting your changes.
See :doc:`setup` for instructions on how to set up Bazel and the full development environment.

Prerequisites
-------------

#. Clone the SCION repository into your workspace.

   .. code-block:: bash

      git clone https://github.com/scionproto/scion
      cd scion

#. Determine the go version used in the Bazel setup; the ``WORKSPACE`` file
   specifies this version in the ``go_register_toolchains`` clause.

   .. literalinclude:: /../WORKSPACE
      :start-at: go_register_toolchains(
      :end-at: )
      :emphasize-lines: 3

   Building with newer go versions *usually* works.

#. Install go. Either follow `the official instructions <https://go.dev/doc/install>`_
   or check the `Ubuntu specific installation options on the golang wiki <https://github.com/golang/go/wiki/Ubuntu>`_.

Build
-----

* **Build only "distributables"**, without development and testing tools

   .. code-block:: bash

      CGO_ENABLED=0 go build -o bin/ ./{router,control,dispatcher,daemon,scion,scion-pki,gateway}/cmd/...

* **Build all**

   .. code-block:: bash

      go build -o bin/ ./...

Options
-------

* sqlite implementations: two different sqlite implementations can be chosen at build time:

  - `modernc/sqlite <https://pkg.go.dev/modernc.org/sqlite>`_: **default**. A pure go implementation of sqlite (transpiled from C).
  - `mattn/go-sqlite3 <https://github.com/mattn/go-sqlite3>`_: A CGO wrapper for the official sqlite implementation.
    It is well established but requires CGO; this makes it impossible to build static binaries and
    executables are dependent on a minimum glibc version.

  Specify build tag (``go build -tags=<...>``) either ``sqlite_modernc`` or ``sqlite_mattn``.

Building with Bazel
===================

Please be aware that the following instructions only result in a minimal build
environment. Not all tests and checks can be run in this setup.
See :doc:`setup` for instructions on how to set up Bazel and the full development environment.

Prerequisites
-------------

#. Clone the SCION repository into your workspace.

   .. code-block:: bash

      git clone https://github.com/scionproto/scion
      cd scion

#. Install Bazel: either follow the official instructions at `<https://bazel.build/install>`_, or
   run our helper script:

   .. code-block::

      tools/install_bazel

#. Remove remote cache options from ``.bazelrc``; the default setup is useful to limit Bazel's
   cache size when contributing to SCION, but requires a running docker container acting as the
   "remote" cache service

   .. code-block::

      sed -e '/--remote_cache=/d' -i .bazelrc

   Alternatively, if you have docker installed, you can run ``./scion.sh bazel-remote`` to start
   the cache service.

Build
-----

* **Build only "distributables"**, without development and testing tools

   .. code-block:: sh

      make build                          # or, ...
      bazel build //:scion                # or, ...
      bazel build //control/cmd/control //router/cmd/router <...>

* **Build all**

   .. code-block:: sh

      make build-dev                      # or, ...
      make                                # or, ...
      bazel build //:scion //:scion-ci

* **Build packages for debian (all target architectures)**

  .. code-block:: sh

     make dist-deb                        # or, ...
     bazel build //dist:deb_all

* **Build packages for openwrt (x86_64 only, currently)**

  .. code-block:: sh

     make dist-openwrt                        # or, ...
     bazel build //dist:openwrt_all

Options
-------

* Bundling the management API documentation with the binaries.

   .. code-block:: sh

      bazel build --//:mgmtapi_bundle_doc=true //:scion

* sqlite implementations: specify a build tag, ``sqlite_modernc`` or ``sqlite_mattn``.

   .. code-block:: sh

      bazel build --define gotags=sqlite_mattn <...>


.. seealso::

   :doc:`setup`
      Instructions for :doc:`installing the full development environment <setup>`.

   :doc:`/manuals/install`
      Information for :doc:`installing SCION from per-built binaries or packages </manuals/install>`.
