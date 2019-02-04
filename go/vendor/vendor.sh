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

# This pipeline has following steps:
# 1. Keep only part of the file that comes after "# Dependencies" comment.
# 2. Filter out only lines with "name"and "importpath" attributes.
# 3. Collapse two subsequent lines (name & importpath) into a single line.
# 4. Parse out the values of the two attributes.
# 5. Remove org_golang_x_sys_windows_registry as it clashes with org_golang_x_sys_windows.
# 6. Iterate through the results and create symbolic links as needed.
cat ../../WORKSPACE \
    | sed -n -e '/# Dependencies/,$p' \
    | grep -E "name|importpath" \
    | sed 'N;s/\n/ /' \
    | sed -e 's/^.*"\(.*\)".*"\(.*\)".*$/\1 \2/' \
    | grep -v org_golang_x_sys_windows_registry \
    | while IFS= read -r LINE
    do
        ARR=($LINE)
        NAME="${ARR[0]}"
        IMPORTPATH="${ARR[1]}"
        mkdir -p $IMPORTPATH
        rmdir $IMPORTPATH
        ln -s $PWD/../../bazel-scion/external/$NAME $IMPORTPATH
    done
