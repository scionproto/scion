#!/bin/bash

# Generates fake dependency tree.
#
# This is just the directory structure with the leafs being symlinks
# to the external dependencies, as downloaded by Bazel.
#
# This makes standard Golang tools work (they assume that the
# external dependencies are on the GOPATH).

set -e

echo "Generating fake external dependency tree in go/vendor"

ROOTDIR=$(dirname "$0")/..
OUTPUT_BASE=$(bazel info output_base)

# First, remove the entire linkfarm so that we don't get stale
# links laying around.
rm -rf $ROOTDIR/go/vendor

# This pipeline has following steps:
# 1. Keep only part of the file that comes after "# Dependencies" comment.
# 2. Filter out only lines with "name" and "importpath" attributes.
# 3. Collapse two subsequent lines (name & importpath) into a single line.
# 4. Parse out the values of the two attributes.
# 5. Iterate through the results and create symbolic links as needed.
cat  $ROOTDIR/WORKSPACE \
    | sed -n -e '/# Dependencies/,$p' \
    | grep -E "name|importpath" \
    | sed 'N;s/\n/ /' \
    | sed -e 's/^.*"\(.*\)".*"\(.*\)".*$/\1 \2/' \
    | while IFS=" " read -r NAME IMPORTPATH
    do
        mkdir -p $ROOTDIR/go/vendor/$(dirname "$IMPORTPATH")
        ln -s $OUTPUT_BASE/external/$NAME $ROOTDIR/go/vendor/$IMPORTPATH
    done
