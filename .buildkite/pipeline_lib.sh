# gen_acceptance generates all the acceptance steps in a given directory.
# args:
#   -1: the directory in which the acceptance tests are.
#   -2: the tests which don't need any setup. (default: none)
gen_acceptance() {
    local accept_dir=${1}
    local no_setup_tests=${2:-""}
    for test in "$accept_dir"/*_acceptance; do
        name="$(basename ${test%_acceptance})"
        echo "  - label: \"AT: $name\""
        echo "    if: build.message !~ /\[doc\]/"
        echo "    command:"
        if [[ ! "${no_setup_tests}" == *"${name}"* ]]; then
            # some tests don't need the global setup, they are just starting a
            # (few) docker container(s) and run a bazel test against it. So no
            # prebuilding of all docker containers is needed.
            echo "      - $accept_dir/ctl gsetup"
        fi
        echo "      - $accept_dir/ctl grun $name"
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

# gen_bazel_test_steps generates steps for bazel tests in the given directory.
# args:
#   -1: the bazel directory in which the tests are.
gen_bazel_test_steps() {
    for test in $(bazel query "kind(test, ${1}/...)" 2>/dev/null); do
        # test has the format //acceptance/<name>:<name>_test
        name=$(echo $test | cut -d ':' -f 1)
        name=${name#"$1/"}
        echo "  - label: \"AT: :bazel: $name\""
        echo "    if: build.message !~ /\[doc\]/"
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
