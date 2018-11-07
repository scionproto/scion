#!/bin/bash

set -e

export BASE=".buildkite"

continue_on_failure() {
    echo "- wait: ~"
    echo "  continue_on_failure: true"
}
export -f continue_on_failure

# begin the pipeline.yml file
"$BASE/common.sh"
echo "steps:"

# setup docker images and start
cat "$BASE/setup.yml"

# do build and linting
cat "$BASE/build.yml"

# Commit container and push to registry
cat "$BASE/push_ci_cntr.yml"

# Unit tests
cat "$BASE/test.yml"

# integration testing
"$BASE/integration.sh"

# run some more tests on master
if [ "$BUILDKITE_BRANCH" == "master" ]; then
    # docker integration testing
    cat "$BASE/docker-integration.yml"
    # acceptance testing
    "$BASE/acceptance.sh"
fi

# Stop docker.sh
cat "$BASE/teardown.yml"

# deploy
cat "$BASE/deploy.yml"
