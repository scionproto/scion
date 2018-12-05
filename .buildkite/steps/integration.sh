#!/bin/bash

set -e

[ -z "$RUN_PR" ] && ARGS="-a"

echo "- label: Integration Tests"
echo "  command:"
echo "  - $BASE/run_step integration $ARGS"
echo "  timeout_in_minutes: 30"
echo "  artifact_paths:"
echo "  - \"artifacts.out/**/*\""
