#!/bin/bash

# This script will create a fake BUILD.bazel file that
# can be used to fetch all external dependencies.
# After the file is generated and stored along the WORKSPACE
# do "bazel fetch //:fetch" to actually dowload the repos.

set -e

ROOTDIR=$(dirname "$0")/..

# Add any bazel packages to prefetch to the beginning of the following block.
cat <<EOF
load("@com_github_jmhodges_bazel_gomock//:gomock.bzl", "gomock")

genrule(
    name = "fetch",
    outs = ["dummy"],
    cmd = "touch dummy",
    tools = [
EOF

cat  $ROOTDIR/WORKSPACE \
    | sed -n -e '/# Dependencies/,$p' \
    | grep -E "name|importpath" \
    | sed 'N;s/\n/ /' \
    | grep -v com_github_jmhodges_bazel_gomock \
    | while IFS=" " read -r LINE
    do
        if [[ $LINE =~ \"(.*)\".*\".*\" ]]; then
            NAME=${BASH_REMATCH[1]}
        else
            echo "External dependency name not found: $LINE"
            exit 1
        fi
        if [[ $LINE =~ \#[[:blank:]]*(.*) ]]; then
            NAME=$NAME//${BASH_REMATCH[1]}
        else
            NAME=$NAME//
        fi
        echo "        \"@$NAME:go_default_library\","
    done

cat <<EOF
    ]
)
EOF
