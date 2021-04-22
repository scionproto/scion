#!/bin/bash

set -e

ROOTDIR=$(dirname "$0")/..
TARGET="${TARGET:-"//:scion"}"

bazel build $TARGET

DSTDIR=${1:-$ROOTDIR/licenses/data}
EXECROOT=$(bazel info execution_root 2>/dev/null)

rm -rf $DSTDIR

(cd $EXECROOT/external; find -L . -iregex '.*\(LICENSE\|COPYING\).*') | while IFS= read -r path ; do
    dst=$DSTDIR/$(dirname $path)
    mkdir -p $dst
    cp $EXECROOT/external/$path $dst
done

# Bazel tools are used only for building.
# We don't need these licenses to be distributed with the containers.
rm -rf $DSTDIR/bazel_tools

# These are not actual licenses.
rm -rf $DSTDIR/com_github_spf13_cobra/cobra
rm -rf $DSTDIR/com_github_uber_jaeger_client_go/scripts
rm -rf $DSTDIR/com_github_uber_jaeger_lib/scripts
rm -rf $DSTDIR/com_github_prometheus_procfs/scripts
rm -rf $DSTDIR/org_uber_go_zap/checklicense.sh
rm -rf $DSTDIR/org_golang_x_tools/gopls/
