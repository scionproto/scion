#!/bin/bash

set -e

ROOTDIR=$(dirname "$0")/..

$ROOTDIR/tools/package-version 0.1.0-citest
bazel build //:all

DSTDIR=${1:-$ROOTDIR/licenses/data}
PROJECT=${2:-scion}

rm -rf $DSTDIR

(cd $ROOTDIR/bazel-$PROJECT/external; find -L . -iregex '.*\(LICENSE\|COPYING\).*') | while IFS= read -r path ; do
    dst=$DSTDIR/$(dirname $path)
    mkdir -p $dst
    cp $ROOTDIR/bazel-$PROJECT/external/$path $dst
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
rm -rf $DSTDIR/com_github_hashicorp_consul_api/operator_license.go
rm -rf $DSTDIR/com_github_opencontainers_image_spec/.tool
