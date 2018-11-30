#!/bin/bash

set -e

echo "- label: Integration Tests"
echo "  command:"
if [ -n "$RUN_ALL_TESTS" ]; then
    echo "  - $BASE/run_step integration -a"
else
    echo "  - $BASE/run_step integration"
fi
echo "  timeout_in_minutes: 30"
echo "  artifact_paths:"
echo "  - \"artifacts.out/**/*\""
