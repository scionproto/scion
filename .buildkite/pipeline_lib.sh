# gen_bazel_test_steps generates steps for bazel tests in the given directory.
# args:
#   -1: the bazel directory in which the tests are.
gen_bazel_test_steps() {
    parallel="${PARALLELISM:-1}"
    echo "  - group: \"Integration Tests :bazel:\""
    echo "    key: integration-tests"
    echo "    if: build.message !~ /\[doc\]/"
    echo "    steps:"

    targets="$(bazel query "attr(tags, integration, tests(//...)) except attr(tags, \"lint|manual\", tests(//...))" 2>/dev/null)"
    for test in $targets; do
        name=${test#//}
        cache=""
        args=""

        if [[ "$test" =~ "go" ]]; then
          args="--test_arg=-test.v"
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

        # Massage the name into a prettier label
        label=$(echo "$name" | sed -e '
          s#:test##
          s#:go_default_test##
          s#^acceptance/#AT: #
          s#^demo/\(.*\):.*#Demo: \1#
          s#\(.*\):go_integration_test$#IT: \1#
          s#tools/cryptoplayground:\(.*\)_test#AT: \1#
        ')
        echo "      - label: \"${label}\""
        if [ "$parallel" != "1" ]; then
        echo "        parallelism: $parallel"
        fi
        echo "        command:"
        echo "          - bazel test --test_output=streamed $test $args $cache"
        echo "        key: \"${name////_}\""
        echo "        artifact_paths:"
        echo "          - \"artifacts.out/**/*\""
        echo "        timeout_in_minutes: 20"
        echo "        retry:"
        echo "          automatic:"
        echo "            - exit_status: -1 # Agent was lost"
        echo "            - exit_status: 255 # Forced agent shutdown"
    done
}
