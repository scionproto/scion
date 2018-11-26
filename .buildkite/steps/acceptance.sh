#!/bin/bash

for test in ./acceptance/*_acceptance; do
    echo "- label: ${test}"
    echo "  command:"
    echo "  - $BASE/all_images pull"
    echo "  - $BASE/run_step run_acceptance $test"
    echo "  artifact_paths:"
    echo "  - \"artifacts.out/**/*\""
done
