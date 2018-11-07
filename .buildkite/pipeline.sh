#!/bin/bash

set -e

export BASE=".buildkite"
STEPS="$BASE/steps"

continue_on_failure() {
    echo "- wait: ~"
    echo "  continue_on_failure: true"
}
export -f continue_on_failure

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

# run some more tests on master
if [ "$BUILDKITE_BRANCH" == "master" ] || [ -n "$RUN_ALL_TESTS" ]; then
    # docker integration testing
    cat "$STEPS/docker-integration.yml"
    # acceptance testing
    "$STEPS/acceptance.sh"
fi

# deploy
cat "$STEPS/deploy.yml"
