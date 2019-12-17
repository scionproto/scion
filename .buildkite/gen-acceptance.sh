#!/bin/bash

for test in ./acceptance/*_acceptance; do
    name="$(basename ${test%_acceptance})"
    echo "  - label: \"Acceptance: $name\""
    echo "    command:"
    echo "      - \"rm -rf \$\$ACCEPTANCE_ARTIFACTS\""
    echo "      - \"mkdir -p \$\$ACCEPTANCE_ARTIFACTS\""
    echo "      - ./acceptance/ctl gsetup"
    echo "      - ./acceptance/ctl grun $name"
    echo "    key: ${name}_acceptance"
    echo "    env:"
    echo "      ACCEPTANCE_ARTIFACTS: \"\$BUILDKITE_BUILD_CHECKOUT_PATH/accept_artifacts\""
    echo "      PYTHONPATH: \"python/:.\""
    echo "    artifact_paths:"
    echo "      - \"artifacts.out/**/*\""
    echo "    retry:"
    echo "      automatic:"
    echo "        - exit_status: -1 # Agent was lost"
    echo "        - exit_status: 255 # Forced agent shutdown"
done
