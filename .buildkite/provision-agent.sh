#!/bin/bash

set -euo pipefail

# The installation scripts are no-ops when nothing has changed.
# To circumvent running any checks (and cluttering the output), we only
# rerun the scripts if any of them have changed since the last run.
if sha1sum --check /tmp/buildkite-scionproto-runner-provision.sum --status; then
  exit 0
fi

echo "~~~ Install build tools"
tools/install_bazel
tools/install_deps

sha1sum tools/install_bazel tools/install_deps tools/env/pip3/deps tools/env/pip3/requirements.txt tools/env/rhel/deps > /tmp/buildkite-scionproto-runner-provision.sum
