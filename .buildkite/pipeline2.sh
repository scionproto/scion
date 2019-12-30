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

# gen_acceptance2 generates steps for bazel tests in acceptance folder.
gen_acceptance2() {
    for test in $(bazel query 'kind(sh_test, //acceptance/...)' 2>/dev/null); do
        # test has the format //acceptance/<name>:<name>_test
        name=$(echo $test | cut -d ':' -f 1)
        name=${name#'//acceptance/'}
        echo "  - label: \"Acceptance: $name\""
        echo "    command:"
        echo "      - mkdir -p \$\$ACCEPTANCE_ARTIFACTS"
        echo "      - bazel test --action_env=ACCEPTANCE_ARTIFACTS $test"
        echo "    key: ${name}_acceptance"
        echo "    artifact_paths:"
        echo "      - \"artifacts.out/**/*\""
        echo "    retry:"
        echo "      automatic:"
        echo "        - exit_status: -1 # Agent was lost"
        echo "        - exit_status: 255 # Forced agent shutdown"
    done
}

cat .buildkite/pipeline_buildlint.yml
gen_acceptance2
gen_acceptance
