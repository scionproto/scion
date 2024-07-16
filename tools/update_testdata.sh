#! /bin/bash

set -euo pipefail

export PATH=$(bazel info output_base)/external/go_sdk/bin:$PATH

folders=$(grep \
            -lR \
            --include=\*_test.go \
            --exclude-dir=bazel-\* \
            "xtest.UpdateGoldenFiles()" . | xargs dirname  | sort  | uniq )

GO_BUILD_TAGS_ARG=$(bazel info --ui_event_filters=-stdout,-stderr --announce_rc --noshow_progress 2>&1 | grep "'build' options" | sed -n "s/^.*--define gotags=\(\S*\).*/-tags \1/p")

echo $folders -update | xargs go test ${GO_BUILD_TAGS_ARG}
echo $folders -count=1 | xargs go test ${GO_BUILD_TAGS_ARG}
