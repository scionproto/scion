#! /bin/bash

set -euo pipefail

export PATH=$(bazel info output_base)/external/go_sdk/bin:$PATH

folders=$(grep \
            -lR \
            --include=\*_test.go \
            --exclude-dir=bazel-\* \
            "xtest.UpdateGoldenFiles()" . | xargs dirname  | sort  | uniq )

echo $folders -update | xargs go test
echo $folders -count=1 | xargs go test
