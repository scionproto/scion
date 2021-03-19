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
        echo "    parallelism: $PARALLELISM"
        echo "    if: build.message !~ /\[doc\]/"
        if [ -n "${SINGLE_TEST}" ]; then
            if [ "${SINGLE_TEST}" != "${name}" ]; then
                echo "    skip: true"
            fi
        else
            if [[ ",${skipped_tests}," = *",${name},"* ]]; then
                echo "    skip: true"
            fi
        fi
        echo "    command:"
        if [[ ! "${no_setup_tests}" == *"${name}"* ]]; then
            # some tests don't need the global setup, they are just starting a
            # (few) docker container(s) and run a bazel test against it. So no
            # prebuilding of all docker containers is needed.
            echo "      - ${accept_dir}/ctl gsetup"
        fi
        echo "      - ${accept_dir}/ctl grun $name"
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
    for test in $(bazel query "attr(tags, integration, tests(${1}/...)) except attr(tags, lint, tests(${1}/...))" 2>/dev/null); do
        name=${test#"$1/"}
        skip=false
        cache="--cache_test_results=\${BAZEL_CACHE_TEST_RESULTS:-auto}"
        parallel="${PARALLELISM:-1}"
        args=""

        if [[ "$test" =~ "go" ]]; then
          args="--test_arg=-test.v"
        fi

        ret=$(bazel query "attr(tags, '\\bskip\\b', $test)" 2>/dev/null)
        if [[ $ret != "" ]]; then
          skip="true"
        fi

        if [ -n "${SINGLE_TEST}" ]; then
          if [[ ! "${name}" =~ "${SINGLE_TEST}" ]]; then
            skip="true"
          fi
          cache="--nocache_test_results"
        fi

        if [ "$parallel" != "1" ]; then
            cache="--nocache_test_results"
        fi

        n=${name/test_/}
        echo "  - label: \"AT: ${n/gateway/gw} :bazel:\""
        echo "    parallelism: $parallel"
        echo "    if: build.message !~ /\[doc\]/"
        echo "    command:"
        echo "      - bazel test $test $args $cache"
        if [ "$skip" = true ]; then
            echo "    skip: true"
        fi
        echo "    key: \"${name}_acceptance\""
        echo "    plugins:"
        echo "      - scionproto/metahook#v0.3.0:"
        echo "          post-command: |"
        echo "            echo \"--- Test outputs:\""
        echo "            cat bazel-testlogs/${1}/${name//://}/test.log"
        echo "            echo \"--- unzip testlogs\""
        echo "            unzip bazel-testlogs/${1}/${name//://}/test.outputs/outputs.zip -d outputs 2>//dev//null || true"
        echo "    artifact_paths:"
        echo "      - \"artifacts.out/**/*\""
        echo "    timeout_in_minutes: 20"
        echo "    retry:"
        echo "      automatic:"
        echo "        - exit_status: -1 # Agent was lost"
        echo "        - exit_status: 255 # Forced agent shutdown"
    done
}
