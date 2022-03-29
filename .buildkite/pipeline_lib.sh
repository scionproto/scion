# gen_bazel_test_steps generates steps for bazel tests in the given directory.
# args:
#   -1: the bazel directory in which the tests are.
gen_bazel_test_steps() {
    targets="$(bazel query "attr(tags, integration, tests(${1}/...)) except attr(tags, \"lint|manual\", tests(${1}/...))" 2>/dev/null)"
    for test in $targets; do
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
          continue
        fi

        if [ -n "${SINGLE_TEST}" ]; then
          if [[ ! "${name}" =~ "${SINGLE_TEST}" ]]; then
            continue
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
