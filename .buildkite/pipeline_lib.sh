# gen_acceptance generates all the acceptance steps in a given directory.
# args:
#   -1: the directory in which the acceptance tests are.
#   -2: the tests which don't need any setup. (default: none)
#   -3: tests to skip (default: none)
gen_acceptance() {
    local accept_dir=${1}
    local no_setup_tests=${2:-""}
    local skipped_tests=${3:-""}
    for test in "$accept_dir"/*_acceptance; do
        name="$(basename ${test%_acceptance})"
        echo "  - label: \"AT: $name\""
        echo "    if: build.message !~ /\[doc\]/"
        if [[ ",${skipped_tests}," = *",${name},"* ]]; then
            echo "    skip: true"
        fi
        echo "    command:"
        if [[ ! "${no_setup_tests}" == *"${name}"* ]]; then
            # some tests don't need the global setup, they are just starting a
            # (few) docker container(s) and run a bazel test against it. So no
            # prebuilding of all docker containers is needed.
            echo "      - ./acceptance/ctl gsetup"
        fi
        echo "      - ./acceptance/ctl grun $name"
        echo "    key: ${name}_acceptance"
        echo "    env:"
        echo "      PYTHONPATH: \"python/:.\""
        echo "      ACCEPTANCE_DIR: \"$accept_dir\""
        echo "    artifact_paths:"
        echo "      - \"artifacts.out/**/*\""
        echo "    timeout_in_minutes: 20"
        echo "    retry:"
        echo "      automatic:"
        echo "        - exit_status: -1 # Agent was lost"
        echo "        - exit_status: 255 # Forced agent shutdown"
    done
}

# gen_bazel_test_steps generates steps for bazel tests in the given directory.
# args:
#   -1: the bazel directory in which the tests are.
gen_bazel_test_steps() {
    for test in $(bazel query "kind(test, ${1}/...)" 2>/dev/null); do
        # test has the format //acceptance/<name>:<name>_test
        name=$(echo $test | cut -d ':' -f 1)
        name=${name#"$1/"}
        echo "  - label: \"AT: $name :bazel:\""
        echo "    if: build.message !~ /\[doc\]/"
        echo "    command:"
        if [[ "$test" =~ "go" ]]; then
            # for go tests add verbose flag.
            echo "      - bazel test $test --test_arg=-test.v --cache_test_results=\${BAZEL_CACHE_TEST_RESULTS:-auto}"
        else
            echo "      - bazel test $test --cache_test_results=\${BAZEL_CACHE_TEST_RESULTS:-auto}"
        fi
        echo "    key: ${name}_acceptance"
        echo "    artifact_paths:"
        echo "      - \"artifacts.out/**/*\""
        echo "    timeout_in_minutes: 20"
        echo "    retry:"
        echo "      automatic:"
        echo "        - exit_status: -1 # Agent was lost"
        echo "        - exit_status: 255 # Forced agent shutdown"
    done
}
