#!/bin/bash

set -e

[ "$RUN_ALL_TESTS" = "y" ] && ARGS="-a"

echo "- label: Integration Tests"
echo "  command:"
echo "  - $BASE/run_step integration $ARGS"
echo "  timeout_in_minutes: 30"
echo "  artifact_paths:"
echo "  - \"artifacts.out/**/*\""
