#!/bin/bash

# This tools builds the perapp images.

set -ex

ROOTDIR=$(dirname "$0")/../..

TMPDIR=$(mktemp -d /tmp/licenses.XXXXXXX)
STAGE=${1:-prod}

# Build the binaries.
# This will fetch everything that haven't been fetched yet.
bazel build //:scion

# Collect the licenses from the bazel cache.
pushd $ROOTDIR/bazel-scion*/external
find . -iregex '.*\(LICENSE\|COPYING\).*' -exec cp --parents '{}' $TMPDIR ';'
popd

# Put the licenses into a tarball.
tar cf $ROOTDIR/docker/perapp/licenses.tar -C $TMPDIR --transform 's,^,licenses/,' .
rm -rf $TMPDIR

# Build the images and push them to local docker repository.
bazel run //docker/perapp:$STAGE

# Remove licenses
tar cvf $ROOTDIR/docker/perapp/licenses.tar --files-from /dev/null
