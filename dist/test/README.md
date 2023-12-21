# Test for Debian packages

This is a minimal test for the debian packages built in dist/BUILD.bazel.

## Run

There are two ways to run this test:

```sh
# Build packages to bazel internal directory and run test
bazel test --test_output=streamed //dist/test:deb_test
```

OR

```sh
# Build packages  .. or any other way to get the packages into deb/
make dist-deb
# Run the test script
dist/test/deb_test.sh
```

## Scope

The test should determine whether

- the packages can be installed
- the binaries in the packages are runnable
- the systemd units in the packages can be used to interact with the SCION services

The test does **not** attempt to simulate a working SCION network.
The assumption is that if the services installed from the packages
can be started (meaning they don't crash immediately after startup), the
findings of the various acceptence and end-to-end integration tests apply.
