#!/bin/bash

set -e

ROOTDIR=$(dirname "$0")/..
echo $ROOTDIR

bazel build //:all

rm -rf $ROOTDIR/licenses/data

find -L $ROOTDIR/bazel-scion/external -iregex '.*\(LICENSE\|COPYING\).*' | cut -d/ -f5- | while IFS= read -r path ; do
    dst=$ROOTDIR/licenses/data/$(dirname $path)
    mkdir -p $dst
    cp $ROOTDIR/bazel-scion/external/$path $dst
done

# Bazel tools are used only for building. We don't need the licenses
# to be distributed in the containers.
rm -rf $ROOTDIR/licenses/data/bazel_tools

# These are not actual licenses.
rm -rf $ROOTDIR/licenses/data/com_github_spf13_cobra/cobra
rm -rf $ROOTDIR/licenses/data/com_github_uber_jaeger_client_go/scripts
rm -rf $ROOTDIR/licenses/data/com_github_uber_jaeger_lib/scripts
rm -rf $ROOTDIR/licenses/data/com_github_prometheus_procfs/scripts
