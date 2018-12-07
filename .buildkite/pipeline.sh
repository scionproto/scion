#!/bin/bash

set -e

export BASE=".buildkite"
STEPS="$BASE/steps"

# if the pipeline is triggered from a PR, run a reduced pipeline
if [ -z "$RUN_ALL_TESTS" ]; then
    [ "$BUILDKITE_PULL_REQUEST" = "false" ] && RUN_ALL_TESTS=y
fi

# begin the pipeline.yml file
"$BASE/common.sh"
echo "steps:"

# build scion image and push
cat "$STEPS/setup.yml"

# do build and linting, then commit container and push
cat "$STEPS/build.yml"

# Unit tests
cat "$STEPS/test.yml"

# build images together with unit tests
if [ "$RUN_ALL_TESTS" = "y" ]; then
    cat "$STEPS/build_all.yml"
fi

# integration testing
"$STEPS/integration.sh"

# conditionally run more tests
if [ "$RUN_ALL_TESTS" = "y" ]; then
    # docker integration testing
    cat "$STEPS/docker-integration.yml"
    # acceptance testing
    "$STEPS/acceptance.sh"
fi

# deploy
cat "$STEPS/deploy.yml"
