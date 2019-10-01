#!/bin/bash

set -e

export BASE=".buildkite"
STEPS="$BASE/steps"
RUN_DOCKER_BUILD="${RUN_DOCKER_BUILD:-true}"

"${BASE}/common.sh"
echo "steps:"

if [[ "$RUN_DOCKER_BUILD" = true ]]; then
    cat "${STEPS}/build_all.yml"
    echo "- wait"
fi

host_acceptance="br_multi br_child br_parent br_peer br_core_multi br_core_childIf br_core_coreIf"

for test in ./acceptance/*_acceptance; do
    name="$(basename ${test%_acceptance})"
    if [[ ! "$name" =~ "$ACCEPTANCE_TEST" ]]; then
        continue
    fi
    RUN_HOST=n
    for host in $host_acceptance; do
        if [ "$host" = "$name" ]; then
            RUN_HOST=y
        fi
    done
    echo "- label: Acceptance - $name"
    if [ "$RUN_HOST" = "y" ]; then
        echo "  env:"
        echo "    ACCEPTANCE_ARTIFACTS: \$SCION_MOUNT/logs/acceptance"
        echo "    DOCKER_ARGS: \"-e ACCEPTANCE_ARTIFACTS=logs/acceptance --privileged --network=host -h $HOSTNAME\""
        echo "  command:"
        echo "  - $BASE/scripts/all_images pull"
        echo "  - $BASE/steps/host_acceptance $test"
    else
        echo "  env:"
        echo "    DOCKER_ARGS: \"-e ACCEPTANCE_ARTIFACTS=logs/acceptance --network=host -h $HOSTNAME\""
        echo "  command:"
        echo "  - $BASE/scripts/all_images pull"
        echo "  - $BASE/run_step run_acceptance $name"
    fi
    echo "  timeout_in_minutes: 10"
    echo "  retry:"
    echo "    automatic:"
    echo "      - exit_status: 5"   # Pull failed
    echo "        limit: 2"
    echo "      - exit_status: -1"  # Agent was lost
    echo "      - exit_status: 255" # Forced agent shutdown
    echo "  artifact_paths:"
    echo "  - \"artifacts.out/**/*\""
done
