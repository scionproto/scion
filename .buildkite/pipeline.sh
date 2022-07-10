#!/bin/bash

set -eou pipefail

# Following values are useful when debugging the CI.
# Modify this value to run only a single test in the CI.
export SINGLE_TEST=
# Modify this value to run each step multiple times.
export PARALLELISM=1

. ./.buildkite/pipeline_lib.sh

cat .buildkite/pipeline.yml
gen_bazel_test_steps
