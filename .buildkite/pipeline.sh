#!/bin/bash

set -e

# gen_acceptance generates all the acceptance steps.
gen_acceptance() {
    for test in ./acceptance/*_acceptance; do
        name="$(basename ${test%_acceptance})"
        echo "  - label: \"Acceptance: $name\""
        echo "    command:"
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

# gen_bazel_acceptance generates steps for bazel tests in acceptance folder.
gen_bazel_acceptance() {
    for test in $(bazel query 'kind(test, //acceptance/...)' 2>/dev/null); do
        # test has the format //acceptance/<name>:<name>_test
        name=$(echo $test | cut -d ':' -f 1)
        name=${name#'//acceptance/'}
        echo "  - label: \":bazel: Acceptance: $name\""
        echo "    command:"
        if [[ "$test" =~ "go" ]]; then
            # for go tests add verbose flag.
            echo "      - bazel test $test --test_arg=-test.v"
        else
            echo "      - bazel test $test"
        fi
        echo "    key: ${name}_acceptance"
        echo "    artifact_paths:"
        echo "      - \"artifacts.out/**/*\""
        echo "    retry:"
        echo "      automatic:"
        echo "        - exit_status: -1 # Agent was lost"
        echo "        - exit_status: 255 # Forced agent shutdown"
    done
}

cat .buildkite/pipeline.yml
gen_bazel_acceptance
gen_acceptance
