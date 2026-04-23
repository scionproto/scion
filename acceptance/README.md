# Acceptance testing framework

This directory contains a set of integration tests.
Each test is defined as a bazel test target, with tag `integration`.
Tests run in parallel, unless they need any global resources (like
network namespaces or hardcoded IPs). For such tests,
`exclusive` tag is used.

Some integration tests use code outside this directory. For example, the
`router_multi` acceptance test cases and main executable are in `tools/braccept`.

## Basic Commands

To run all integration tests which include the acceptance tests, execute one of
the following (equivalent) commands

```bash
make test-integration                # or,
bazel test --config=integration_all  # or,
bazel test --config=integration //...
```

Run a subset of the tests by specifying a different list of targets:

```bash
bazel test --config=integration //acceptance/cert_renewal:all //acceptance/trc_update/...
bazel test --config=integration //acceptance/router_multi:all --cache_test_results=no
```

The following flags can be helpful when running individual tests:

- `--test_output=streamed` to display test output to the screen immediately
- `--cache_test_results=no` or `-t-` to re-run tests after a cached success
- `--local_test_jobs=N` to control how many tests run in parallel

When using `make test-integration`, extra Bazel flags can be passed via `ARGS`:

```bash
make test-integration ARGS="--local_test_jobs=3"
```

## Manual Testing

Some of the tests are defined using a common framework, implemented by the
bazel rules `topogen_test` and `raw_test` (in [raw.bzl](acceptance/common/raw.bzl)).
These test cases allow more fine grained interaction.

```bash
# Run topogen and start containers, or other relevant setup
bazel run //<test-package>:<target>_setup
# Run the actual test
bazel run //<test-package>:<target>_run
# ... interact with setup, see state in /tmp/artifacts-scion ...
# Shutdown and cleanup
bazel run //<test-package>:<target>_teardown
```

For example:

```bash
bazel run //acceptance/router_multi:test_bfd_setup
bazel run //acceptance/router_multi:test_bfd_run
bazel run //acceptance/router_multi:test_bfd_teardown
```

See [common/README](common/README.md) for more information about the internal
structure of these tests.
