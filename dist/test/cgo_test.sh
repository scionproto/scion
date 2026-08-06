#!/bin/bash

# Checks that the packaged binaries are built with cgo, for every release architecture.
#
# The sqlite driver (github.com/mattn/go-sqlite3) needs cgo. Without it the driver still
# compiles, but every call fails at run time. The control service and the daemon hit that
# on their first database access, i.e. at startup. That is how v0.15.0 shipped, see
# https://github.com/scionproto/scion/issues/4960.

set -euo pipefail

# Space-separated list of the binaries that go into the deb and rpm packages, for all
# release architectures.
binaries=${SCION_PACKAGE_BINARIES?}

stub="Binary was compiled with 'CGO_ENABLED=0', go-sqlite3 requires cgo to work"
# Only present if the sqlite C sources were compiled in.
symbol="sqlite3_open_v2"

checked=0
failed=0
for binary in ${binaries}; do
    checked=$((checked + 1))
    if grep -qa "${stub}" "${binary}"; then
        echo "FAIL: ${binary}: built without cgo, sqlite driver is a stub"
        failed=$((failed + 1))
        continue
    fi
    if ! grep -qa "${symbol}" "${binary}"; then
        echo "FAIL: ${binary}: no ${symbol}, sqlite was not compiled in"
        failed=$((failed + 1))
    fi
done

if [ "${checked}" -eq 0 ]; then
    echo "FAIL: no binaries to check, the test is not wired up correctly"
    exit 1
fi

if [ "${failed}" -ne 0 ]; then
    echo "${failed} of ${checked} binaries were built without cgo;"
    echo "check the PACKAGE_PLATFORMS definition and the toolchains it relies on, in"
    echo "//dist/BUILD.bazel and //MODULE.bazel respectively."
    exit 1
fi

echo "Success! ${checked} binaries are built with cgo."
