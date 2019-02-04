#!/bin/bash

# Generates fake dependency tree.
#
# This is just the directory structure with the leafs being symlinks
# to the external dependencies, as downloaded by Bazel.
#
# This make standard Golang tools work (they assume that the
# external dependencies are on the GOPATH).

set -e

echo "Generating fake external dependency tree in go/vendor"

rm -rf */

jq -r '.[] | select(.link!=false) | "\(.name) \(.importpath)"' vendor.json |
    while IFS= read -r LINE
    do
        ARR=($LINE)
        NAME="${ARR[0]}"
        IMPORTPATH="${ARR[1]}"
        mkdir -p $IMPORTPATH
        rmdir $IMPORTPATH
        ln -s $PWD/../../bazel-scion/external/$NAME $IMPORTPATH
    done
