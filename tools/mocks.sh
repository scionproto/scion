#!/bin/bash

# Generates links to mocks in the source tree.
# This makes standard Golang tools work.

set -ex

echo "Generating links to mocks"

ROOTDIR=$(dirname "$0")/..

bazel query 'kind(gomock, //...)' \
    | grep -vE "_gomock_prog$" \
    | sed -e 's/^\/\/\(.*\):\(.*\)$/\1 \2/' \
    | while IFS=" " read -r DIR NAME
    do
        echo "$DIR === $NAME"
        ln -r -s -f $ROOTDIR/bazel-bin/$DIR/$NAME.go $ROOTDIR/$DIR/$NAME.go
    done
