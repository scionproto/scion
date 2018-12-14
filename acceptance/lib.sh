. acceptance/color.sh

run_command() {
    local cmd="$1"
    local out="$2"

    # Save the state of errexit
    [[ $- =~ e ]] && local e_set=y
    # Unset errexit, so that $cmd failing won't quit the script.
    set +e

    # Run cmd, save return value.
    $cmd &>> "${out:-/dev/stdout}"
    local ret=$?

    # Re-set errexit if it was previously set.
    [ -n "$e_set" ] && set -e

    if [[ -n "$out" && $ret -ne 0 ]]; then
        cat "$out"
    fi
    return $ret
}

stop_infra() {
    ./scion.sh stop
}

build_docker_base() {
    ./docker.sh base
}

build_docker_scion() {
    ./docker.sh build
}

build_docker_tester() {
    ./docker.sh tester
}

build_docker_perapp() {
    make -C docker/perapp
}

artifacts_dir() {
    export ACCEPTANCE_ARTIFACTS="${ACCEPTANCE_ARTIFACTS:-$(mktemp -d /tmp/acceptance-artifacts-$(date +"%Y%m%d-%H%M%S").XXXXXXX)}"
    echo "Acceptance artifacts saved to $ACCEPTANCE_ARTIFACTS"
}

global_setup() {
    artifacts_dir
    local out_dir="$ACCEPTANCE_ARTIFACTS"
    set -e
    print_green "[==========]"
    print_green "[>---------]" "Global test environment set-up"
    print_green "[->--------]" "Stopping infra"
    run_command stop_infra ${out_dir:+$out_dir/global_setup_pre_clean.out}
    find logs -mindepth 1 -maxdepth 1 -not -path '*/\.*' -exec rm -r {} +
    print_green "[-->-------]" "Building local code"
    run_command make ${out_dir:+$out_dir/global_setup_make.out}
    print_green "[--->------]" "Building scion_base docker image"
    run_command build_docker_base ${out_dir:+$out_dir/global_setup_docker_base.out}
    print_green "[---->-----]" "Building scion docker image"
    run_command build_docker_scion ${out_dir:+$out_dir/global_setup_docker_scion.out}
    print_green "[---->-----]" "Building tester docker images"
    run_command build_docker_tester ${out_dir:+$out_dir/global_setup_docker_scion.out}
    print_green "[----->----]" "Building per-app docker images"
    run_command build_docker_perapp ${out_dir:+$out_dir/global_setup_docker_perapp.out}
    print_green "[>>>>>>>>>>]" "Global test environment set-up finished"
    set +e
}

test_setup_wrapper() {
    if run_command "$TEST_PROGRAM setup" "$1"; then
        print_green "[ SETUP    ]" "$TEST_NAME"
        return 0
    else
        stats_failed=$((stats_failed+1))
        print_red "[ SETUP    ]" "$TEST_NAME"
        return 1
    fi
}

test_run_wrapper() {
    print_green "[  RUN     ]" "$TEST_NAME"
    if run_command "$TEST_PROGRAM run" "$1"; then
        stats_passed=$((stats_passed+1))
        print_green "[   OK     ]" "$TEST_NAME"
        return 0
    else
        stats_failed=$((stats_failed+1))
        print_red "[   FAILED ]" "$TEST_NAME"
        return 1
    fi
}

save_logs() {
    local out_dir="${ACCEPTANCE_ARTIFACTS:?}"
    mkdir -p "$out_dir/$TEST_NAME/logs"
    mv logs/* "$out_dir/$TEST_NAME/logs"
}

test_teardown_wrapper() {
    if run_command "$TEST_PROGRAM teardown" "$1"; then
        print_green "[ TEARDOWN ]" "$TEST_NAME"
        return 0
    else
        print_red "[ TEARDOWN ]" "$TEST_NAME"
        return 1
    fi
}

global_run() {
    local regex_matcher="$1"
    for i in ./acceptance/*_acceptance; do
        stats_total=$((stats_total+1))
        TEST_PROGRAM="$i/test"
        TEST_NAME=$($TEST_PROGRAM name)
        print_green "[----------]" "Test found: $TEST_NAME"
        if [[ "$TEST_NAME" =~ $regex_matcher ]]; then
            global_run_single "$TEST_PROGRAM"
            local fatal_teardown=$?
            save_logs
            if [ $fatal_teardown -ne 0 ]; then
                print_red "[  FATAL   ]" "Teardown failed, stopping test suite"
                exit 1
            fi
        else
            print_yellow "[  SKIPPED ]" "$TEST_NAME"
            stats_skipped=$((stats_skipped+1))
        fi
    done
}

global_run_single() {
    local out_dir="${ACCEPTANCE_ARTIFACTS:?}"
    TEST_PROGRAM="${1:?}"
    TEST_NAME=$($TEST_PROGRAM name)
    mkdir -p "$out_dir/$TEST_NAME"
    SETUP_FILE="$out_dir/$TEST_NAME/setup.out"
    RUN_FILE="$out_dir/$TEST_NAME/run.out"
    TEARDOWN_FILE="$out_dir/$TEST_NAME/teardown.out"
    test_setup_wrapper "$SETUP_FILE" && \
        test_run_wrapper "$RUN_FILE"
    test_teardown_wrapper "$TEARDOWN_FILE"
}

print_results() {
    print_green  "[==========]" "$((stats_total-stats_skipped)) tests out of $stats_total tests ran."
    if [ $stats_passed -gt 0 ]; then
        print_green "[  PASSED  ]" "$stats_passed tests."
    fi
    if [ $stats_failed -gt 0 ]; then
        print_red "[   FAILED ]" "$stats_failed tests."
    fi
    if [ $stats_skipped -gt 0 ]; then
        print_yellow "[ SKIPPED  ]" "$stats_skipped tests."
    fi
}

global_teardown() {
    print_green "[----------]" "Global test environment tear-down"
    print_results
}
