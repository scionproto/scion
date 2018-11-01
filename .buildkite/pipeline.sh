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

# do build and testing
cat "$BASE/build.yml"
# integration testing
"$BASE/integration.sh"
continue_on_failure
cat "$BASE/logs.yml"

# run some more tests on master
if [ "$BUILDKITE_BRANCH" == "master" ]; then
    cat "$BASE/docker-integration.yml"
    continue_on_failure
    cat "$BASE/logs.yml"
    continue_on_failure

    # acceptance testing
    "$BASE/acceptance.sh"
fi

# deploy
cat "$BASE/deploy.yml"

# Stop docker.sh
cat "$BASE/teardown.yml"
