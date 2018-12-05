#!/bin/bash

set -e

export BASE=".buildkite"
STEPS="$BASE/steps"

# if the pipeline is triggered from a PR, run a reduced pipeline
[ "${BUILDKITE_PULL_REQUEST:-false}" != "false" ] && export RUN_PR=y

# begin the pipeline.yml file
"$BASE/common.sh"
echo "steps:"

# setup docker images, lint and build code
cat "$STEPS/setup.yml"

# Unit tests
cat "$STEPS/test.yml"

# build images together with unit tests
if [ -z "$RUN_PR" ]; then
    cat "$STEPS/build_all.yml"
fi

# integration testing
"$STEPS/integration.sh"

# conditionally run more tests
if [ -z "$RUN_PR" ]; then
    # docker integration testing
    cat "$STEPS/docker-integration.yml"
    # acceptance testing
    "$STEPS/acceptance.sh"
fi

# deploy
cat "$STEPS/deploy.yml"
