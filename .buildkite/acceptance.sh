#!/bin/bash

for test in ./acceptance/*_acceptance; do
    echo "- label: ${test}"
    echo "  command:"
    echo "  - find \$SCION_MOUNT/logs -mindepth 1 -maxdepth 1 -not -path '*/\.*' -exec rm -r {} +"
    echo "  - ./docker.sh exec ${test}/test setup"
    echo "  - ./docker.sh exec ${test}/test run"
    echo "  - ./docker.sh exec ${test}/test teardown"
    echo "  artifact_paths:"
    echo "  - \"artifacts.out/**/*\""
    continue_on_failure
    cat "$BASE/logs.yml"
    continue_on_failure
done
