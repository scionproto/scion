#!/bin/bash

set -e

# gen_acceptance generates all the acceptance steps.
gen_acceptance() {
    for test in ./acceptance/*_acceptance; do
        name="$(basename ${test%_acceptance})"
        echo "  - label: \"Acceptance: $name\""
        echo "    command:"
        echo "      - \"mkdir -p \$\$ACCEPTANCE_ARTIFACTS\""
        echo "      - ./acceptance/ctl gsetup"
        echo "      - ./acceptance/ctl grun $name"
        echo "    key: ${name}_acceptance"
        echo "    env:"
        echo "      PYTHONPATH: \"python/:.\""
        echo "    artifact_paths:"
        echo "      - \"artifacts.out/**/*\""
        echo "    retry:"
        echo "      automatic:"
        echo "        - exit_status: -1 # Agent was lost"
        echo "        - exit_status: 255 # Forced agent shutdown"
    done
}

cat .buildkite/pipeline_buildlint.yml
gen_acceptance
