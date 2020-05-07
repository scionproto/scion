#!/bin/bash

set -eou pipefail

. ./.buildkite/pipeline_lib.sh

cat .buildkite/pipeline.yml
gen_bazel_test_steps //acceptance
gen_acceptance ./acceptance
