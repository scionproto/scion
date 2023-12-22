# gen_bazel_test_steps generates steps for bazel tests in the given directory.
# args:
#   -1: the bazel directory in which the tests are.
gen_bazel_test_steps() {
    parallel="${PARALLELISM:-1}"
    echo "  - group: \"Integration Tests :bazel:\""
    echo "    key: integration-tests"
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
          s#^demo/\([^:]*\).*#Demo: \1#
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
        echo "        plugins:"
        echo "          - scionproto/metahook#v0.3.0:"
        echo "              pre-command: .buildkite/cleanup-leftovers.sh"
        echo "              pre-artifact: tar -chaf bazel-testlogs.tar.gz bazel-testlogs"
        echo "              pre-exit: .buildkite/cleanup-leftovers.sh"
        echo "        artifact_paths:"
        echo "          - \"bazel-testlogs.tar.gz\""
        echo "        timeout_in_minutes: 20"
        echo "        retry:"
        echo "          manual:"
        echo "            permit_on_passed: true"
        echo "          automatic:"
        echo "            - exit_status: -1 # Agent was lost"
        echo "            - exit_status: 255 # Forced agent shutdown"
        echo "            - exit_status: 3 # Test may be flaky or it just didn't pass"
        echo "              limit: 2"
    done
}
