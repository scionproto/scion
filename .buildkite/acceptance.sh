#!/bin/bash

for test in ./acceptance/*_acceptance; do
    echo "- label: ${test}"
    echo "  command:"
    echo "  - rm -f $SCION_MOUNT/logs/*"
    echo "  - ./docker.sh exec ${test}/test setup"
    echo "  - ./docker.sh exec ${test}/test run"
    echo "  - ./docker.sh exec ${test}/test teardown"
    echo "  artifact_paths:"
    echo "  - \"artifacts.out/**/*\""
    continue_on_failure
    cat "$BASE/logs.yml"
    continue_on_failure
done
