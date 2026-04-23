# gen_bazel_test_steps generates steps for bazel tests in the given directory.
# args:
#   -1: the bazel directory in which the tests are.
gen_bazel_test_steps() {
    parallel="${PARALLELISM:-1}"
    echo "  - group: \"Integration Tests :bazel:\""
    echo "    key: integration-tests"
    echo "    steps:"

    # Split tests into exclusive (must run alone) and parallel-safe groups.
    all_targets="$(bazel query "attr(tags, integration, tests(//...)) except attr(tags, \"lint|manual\", tests(//...))" 2>/dev/null)"
    exclusive_targets="$(bazel query "attr(tags, exclusive, attr(tags, integration, tests(//...))) except attr(tags, \"lint|manual\", tests(//...))" 2>/dev/null)"
    parallel_targets=""
    for test in $all_targets; do
        if [ -n "${SINGLE_TEST}" ]; then
            name=${test#//}
            if [[ ! "${name}" =~ "${SINGLE_TEST}" ]]; then
                continue
            fi
        fi
        is_exclusive=false
        for ex in $exclusive_targets; do
            if [ "$test" = "$ex" ]; then
                is_exclusive=true
                break
            fi
        done
        if [ "$is_exclusive" = "false" ]; then
            parallel_targets="$parallel_targets $test"
        fi
    done

    # Emit a single step for all parallel-safe tests.
    if [ -n "$parallel_targets" ]; then
        cache=""
        if [ -n "${SINGLE_TEST}" ] || [ "$parallel" != "1" ]; then
            cache="--nocache_tesx§t_results"
        fi

        echo "      - label: \"Other integration tests (parallel)\""
        echo "        command:"
        echo "          - echo '--- Targets' && echo '$parallel_targets' | tr ' ' '\n' | sort"
        echo "          - bazel test --config=integration --local_test_jobs=HOST_CPUS*.75 $cache $parallel_targets"
        echo "        key: \"integration_parallel\""
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
    fi

    # Emit individual steps for exclusive tests.
    for test in $exclusive_targets; do
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
