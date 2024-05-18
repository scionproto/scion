*******
Testing
*******

Basics
======

* **Run all tests**:
  To execute the entire test suite in your local :doc:`development environment </dev/setup>`, run

   .. code-block:: sh

      make test               # to run unit-tests
      make test-integration   # to run integration/"acceptance" tests

   These make targets are a convenient way to invoke the actual build and test tool, ``bazel``.
   See the :file-ref:`Makefile` for the definition of the targets.
   The referenced bazel ``--config`` are defined in :file-ref:`.bazelrc`.

* **Unit tests for individual go packages**:
  To run tests for individual go packages, like for example ``pkg/snet``, invoke ``bazel test``
  directly and specify the test as a bazel target:

   .. code-block:: sh

      bazel test --config=unit //pkg/snet:go_default_test # unit test for exactly pkg/snet
      bazel test --config=unit //pkg/snet/...             # unit tests for all packages under pkg/snet

* **Run individual go test cases**:
  Use the ``--test_filter=<regex>`` option to filter on the level of individual test cases.

   .. code-block:: sh

      bazel test --config=unit //pkg/snet:go_default_test --test_filter=TestPacketSerializeDecodeLoop

* **Useful bazel test flags**: Finding a flag in the `bazel command line reference <https://bazel.build/reference/command-line-reference>`_
  can be tricky, so here are some pointers:

   * |bazel-nocache_test_results|_: disable the default caching of test results, to force rerunning them.
   * |bazel-test_output-streamed|_: show all test output
   * |bazel-test_arg|_: Pass flags to the `go testing infrastructure <https://pkg.go.dev/cmd/go#hdr-Testing_flags>`_.

     For example, instead of the ``--test_filter=<regex>`` mentioned above we could also filter
     tests with ``--test_arg=-test.run=<regex>``.
     This can be used to run benchmarks.

.. |bazel-nocache_test_results| replace:: ``--nocache_test_results`` / ``-t-``
.. _bazel-nocache_test_results: https://bazel.build/reference/command-line-reference#flag--cache_test_results

.. |bazel-test_output-streamed| replace:: ``--test_output=streamed``
.. _bazel-test_output-streamed: https://bazel.build/reference/command-line-reference#flag--test_output

.. |bazel-test_arg| replace:: ``--test_arg=...``
.. _bazel-test_arg: https://bazel.build/reference/command-line-reference#flag--test_arg

Advanced
========

.. toctree::
   :maxdepth: 1

   buildkite
   mocks
   goldenfiles
   crypto
   hiddenpaths
   Integration/Acceptence Tests (README) <https://github.com/scionproto/scion/blob/master/acceptance/README.md>
   benchmarking
