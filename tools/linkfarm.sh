#!/bin/bash

# Manages links to the generated files in the source tree.
# This makes standard Golang tools work, but it  breaks hermeticity of the source tree.
# Use at your own danger.
#
# Usage:
#     linkfarm create
#     linkfarm delete
#
# NOTE WELL:
# - Never use this for any kind of automated workload.
# - Make sure not to commit the generated links to git.
# - The links will be dangling until the mocks are actually generated.
# - The links are never cleaned up automatically.
# - If you switch between branches, the links can break.

set -e

echo "Generating links to mocks"

ROOTDIR=$(dirname "$0")/..

bazel query 'kind(gomock, //...)' \
    | grep -vE '_gomock_prog$' \
    | sed -r 's@^//(.*):(.*)$@\1 \2@' \
    | while IFS=" " read -r DIR NAME
    do
        echo "$DIR/$NAME.go"
        case $1 in
            create) ln -n -s -f $ROOTDIR/bazel-bin/$DIR/$NAME.go $ROOTDIR/$DIR/$NAME.go ;;
            delete) rm -f $ROOTDIR/$DIR/$NAME.go ;;
            *)      echo "Invalid command $1"; exit 1 ;;
        esac
    done
