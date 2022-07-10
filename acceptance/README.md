# Acceptance testing framework

This directory contains a set of integration tests.
Each test is defined as a bazel test target, with tags `integration` and `exclusive`.

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
```

The following the flags to bazel test can be helpful when running individual tests:

- `--test_output=streamed` to display test output to the screen immediately
- `--cache_test_results=no` or `-t-` to re-run tests after a cached success

## Manual Testing

Some of the tests are defined using a common framework, defined in the
bazel rules `topogen_test` and `raw_test`.
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

See [common/README](common/README.md) for more information about the internal
structure of these tests.
