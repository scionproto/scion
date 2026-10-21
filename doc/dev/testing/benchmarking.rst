****************
Router Benchmark
****************

:program:`acceptance/router_benchmark/benchmark.py` is a tool to benchmark an external router.

Run it with ``bazel run //acceptance/router_benchmark:benchmark``.
Options go after ``--``.

Without any options, the tool outputs instructions. Those instructions comprise how to configure
the subject router and how to re-execute the tool so it actually carries out the measurement.

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

Router benchmark acceptance tests
=================================

The benchmark harness is also wrapped in two Bazel tests that set up a local topology and
benchmark the router in it:

.. code-block:: sh

   bazel test --test_output=streamed //acceptance/router_benchmark:test_inet
   bazel test --test_output=streamed //acceptance/router_benchmark:test_afxdp

These are tagged ``manual``. They are not part of the CI build nor
of ``//...`` wildcards. CI agents are shared VMs, whose throughput says little about the router.

Both tests run over veth pairs, which lack ``XDP_ZEROCOPY``, so ``test_afxdp`` always runs in
``XDP_COPY`` mode. For zero-copy numbers, use :program:`benchmark.py` with a router whose NIC
supports it. Performance regression testing is scheduled on baremetal.
