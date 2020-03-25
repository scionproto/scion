#!/bin/bash

# This tools builds the perapp images.

set -ex

ROOTDIR=$(dirname "$0")/../..

STAGE=${1:-prod}

# Build the binaries.
# This will fetch everything that haven't been fetched yet.
bazel build //:scion

# Build the images and push them to local docker repository.
bazel run //docker/perapp:$STAGE
