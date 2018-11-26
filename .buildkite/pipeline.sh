#!/bin/bash

set -e

export BASE=".buildkite"
STEPS="$BASE/steps"

[ "$BUILDKITE_BRANCH" == "master" ] && RUN_ALL_TESTS=y

# begin the pipeline.yml file
"$BASE/common.sh"
echo "steps:"

# setup docker images and start
cat "$STEPS/setup.yml"

# do build and linting
cat "$STEPS/build.yml"

# Commit container and push to registry
cat "$STEPS/push_ci_cntr.yml"

# Unit tests
cat "$STEPS/test.yml"

# integration testing
"$STEPS/integration.sh"

# conditionally run more tests
if [ -n "$RUN_ALL_TESTS" ]; then
    cat "$STEPS/build_all.yml"
    # docker integration testing
    cat "$STEPS/docker-integration.yml"
    # acceptance testing
    "$STEPS/acceptance.sh"
fi

# deploy
cat "$STEPS/deploy.yml"
