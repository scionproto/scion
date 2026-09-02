****************
Router Benchmark
****************

:program:`acceptance/router_benchmark/benchmark.py` is a tool to benchmark an external router.

The usage is simply: ``acceptance/router_benchmark/benchmark.py``.

Without any options, the tool outputs instructions. Those instructions comprise how to configure
the subject router and how to re-execute the tool so it actually carries the measurement.

In order to accomplish the tool's instructions one will need to:

* run two microbenchmarks on the subject router: :program:`coremark` and :program:`mmbm`.
* configure :program:`scion-router` on the subject router with a custom configuration and topology.
* configure two of the subject router's interfaces.
* connect these interfaces to two interfaces of the host where :program:`benchmark.py` is going to
  run.

If the subject router is an *X86_64* platform running *Openwrt*, then one should install the
package *scion-bmtools*, which will not only configure :program:`scion-router` for benchmarking,
but will also run the :program:`coremark` and :program:`mmbm` microbenchmarks and make their
results available for pickup by :program:`benchmark.py`.

Otherwise these operations still have to be carried out manually. The :program:`mmbm` and
:program:`coremark` tools can be found in: ``bazel-bin/tools/mmbm/mmbm_/mmbm`` and
``bazel-bin/tools/coremark/coremark``.

Router benchmark acceptance test
================================

The benchmark harness is also wrapped in a Bazel test that sets up a local topology and
benchmarks the router in it:

.. code-block:: sh

   bazel test --test_output=streamed //acceptance/router_benchmark:test

This test is tagged ``manual``. It is not part of the CI build nor of ``//...`` wildcards.
CI agents are shared, virtualized machines, so the throughput they measure says little
about the router. Performance regression testing is scheduled on baremetal instead.
