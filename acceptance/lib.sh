. acceptance/color.sh

run_command() {
    local cmd="$1"
    local out="$2"

    $cmd &>> "${out:-/dev/stdout}"
    local ret=$?
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

build_docker_perapp() {
    make -C docker/perapp
}

global_setup() {
    local out_dir="$ARTIFACTS_FOLDER"
    set -e
    print_green "[==========]"
    print_green "[>---------]" "Global test environment set-up"
    print_green "[->--------]" "Stopping infra"
    run_command stop_infra ${out_dir:+$out_dir/global_setup_pre_clean.out}
    rm -f logs/*
    print_green "[-->-------]" "Building scion_base docker image"
    run_command build_docker_base ${out_dir:+$out_dir/global_setup_docker_base.out}
    print_green "[--->------]" "Building scion docker image"
    run_command build_docker_scion ${out_dir:+$out_dir/global_setup_docker_scion.out}
    print_green "[---->-----]" "Building per-app docker images"
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
    local out="$1"
    mkdir -p "$out/$TEST_NAME/logs"
    mv logs/* "$out/$TEST_NAME/logs"
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
    local out="$ARTIFACTS_FOLDER"
    local regex_matcher="$1"
    for i in ./acceptance/*_acceptance; do
        stats_total=$((stats_total+1))
        TEST_PROGRAM="$i/test"
        TEST_NAME=$($TEST_PROGRAM name)
        print_green "[----------]" "Test found: $TEST_NAME"
        if [[ "$TEST_NAME" =~ "$regex_matcher" ]]; then
            mkdir -p "$out/$TEST_NAME"
            SETUP_FILE="$out/$TEST_NAME/setup.out"
            RUN_FILE="$out/$TEST_NAME/run.out"
            TEARDOWN_FILE="$out/$TEST_NAME/teardown.out"
            test_setup_wrapper "$SETUP_FILE" && \
                test_run_wrapper "$RUN_FILE"
            test_teardown_wrapper "$TEARDOWN_FILE"
            local fatal_teardown=$?
            save_logs "$out"
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
