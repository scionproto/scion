#! /bin/bash

set -euo pipefail

export PATH=$PATH:$(bazel info output_base)/external/go_sdk/bin

folders=$(grep \
            -lR \
            --include=\*_test.go \
            --exclude-dir=bazel-\* \
            "xtest.UpdateGoldenFiles()" . | xargs dirname  | sort  | uniq )
for f in $folders; do
  pushd  $f >/dev/null
  echo "$f"
  go test . -count=1
  go test . -update
  go test . -count=1
  popd  >/dev/null
done
