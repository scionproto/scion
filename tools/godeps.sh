#!/bin/bash

# This script uses gazelle to generate go_deps.bzl from go.mod.
# You don't need to invoke this directly, just run `make go_deps.bzl`.

set -e

ROOTDIR=$(dirname "$0")/..

# Wipe go_deps.bzl file first, -prune seems ineffective
cat <<EOF > $ROOTDIR/go_deps.bzl
# Generated from go.mod by gazelle. DO NOT EDIT
load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_deps():
  pass
EOF

bazel run //:gazelle -- update-repos -from_file=go.mod -to_macro=go_deps.bzl%go_deps
