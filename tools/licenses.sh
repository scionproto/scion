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
