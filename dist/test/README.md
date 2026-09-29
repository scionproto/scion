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

## Architecture coverage

We release deb and rpm packages for amd64, arm64, i386 and armel. These tests install and
start the packages, so they only cover architectures the agent can execute:

| Architecture | Covered by             | Note                                               |
|--------------|------------------------|----------------------------------------------------|
| amd64        | `deb_test`, `rpm_test` | packages installed and started, every pull request |
| i386         | `deb_test_i386`        | the same, but release builds only (tagged manual)  |
| arm64        | `cgo_test_arm64` only  | binaries inspected, never run, see below           |
| armel        | `cgo_test_arm` only    | binaries inspected, never run, see below           |

`cgo_test` covers *all* release architectures and runs on every pull request.
It only inspects the binaries instead of running them. It exists because
the v0.15.0 packages were built without cgo and shipped a sqlite driver stub that
failed at startup, see [#4960](https://github.com/scionproto/scion/issues/4960).

`make dist-test-release` runs the full set.
The release pipeline invokes it for tagged builds.

To also execute arm64 and armel, the agents need `qemu-user-static` and `binfmt-support`
(add them to `tools/env/debian/pkgs.txt`, installed by `provision-agent.sh`), and
`deb_test.sh` needs to accept those architectures. Note that systemd under qemu-user is
fragile; starting the service binaries directly is likely more reliable there.
