#!/bin/bash

. acceptance/color.sh

run_command() {
    local COMMAND="$1"
    local OUTPUT_FILE="$2"
    if [[ -n "$OUTPUT_FILE" ]]; then
        "$COMMAND" &>> "$OUTPUT_FILE"
    else
        "$COMMAND"
    fi
    if [ $? -eq 0 ]; then
        true
    else
        if [[ -n "$OUTPUT_FILE" ]]; then
            cat "$OUTPUT_FILE"
        fi
        false
    fi
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
    local ARTIFACTS_FOLDER="$1"
    set -e
    print_green "[==========]"
    print_green "[----------]" "Global test environment set-up"
    if [[ -n $ARTIFACTS_FOLDER ]]; then
        mkdir "$ARTIFACTS_FOLDER"
        local SETUP_PRE_CLEAN="${ARTIFACTS_FOLDER}/global_setup_pre_clean.out"
        local SETUP_DOCKER_BASE="${ARTIFACTS_FOLDER}/global_setup_docker_base.out"
        local SETUP_DOCKER_SCION="${ARTIFACTS_FOLDER}/global_setup_docker_scion.out"
        local SETUP_DOCKER_PERAPP="${ARTIFACTS_FOLDER}/global_setup_docker_perapp.out"
    fi
    run_command stop_infra $SETUP_PRE_CLEAN
    rm -f logs/*
    run_command build_docker_base $SETUP_DOCKER_BASE
    run_command build_docker_scion $SETUP_DOCKER_SCION
    run_command build_docker_perapp $SETUP_DOCKER_PERAPP
}

test_setup_wrapper() {
    if run_command test_setup "$1"; then
        print_green "[ SETUP    ]" "$TEST_NAME" && true
    else
        stats_failed=$((stats_failed+1))
        print_red "[ SETUP    ]" "$TEST_NAME" && false
    fi
}

test_run_wrapper() {
    print_green "[  RUN     ]" "$TEST_NAME"
    if run_command test_run "$1"; then
        stats_passed=$((stats_passed+1))
        print_green "[   OK     ]" "$TEST_NAME" && true
    else
        stats_failed=$((stats_failed+1))
        print_red "[   FAILED ]" "$TEST_NAME" && false
    fi
}

save_logs() {
    local ARTIFACTS_FOLDER="$1"
    cp -R logs "$ARTIFACTS_FOLDER/$TEST_NAME/"
}

test_teardown_wrapper() {
    run_command test_teardown "$1"
    if run_command test_teardown "$1"; then
        print_green "[ TEARDOWN ]" "$TEST_NAME" && true
    else
        print_read "[ TEARDOWN ]" "$TEST_NAME" && false
    fi
}

global_run() {
    local ARTIFACTS_FOLDER="$1"
    for i in ./acceptance/*_acceptance; do
        stats_total=$((stats_total+1))
        . $i/test.sh
        print_green "[----------]" "Test found: $TEST_NAME"

        if [[ "$TEST_NAME" =~ "$TEST_REGEX_MATCHER" ]]; then
            mkdir -p "$ARTIFACTS_FOLDER/$TEST_NAME"
            SETUP_FILE="$ARTIFACTS_FOLDER/$TEST_NAME/setup.out"
            RUN_FILE="$ARTIFACTS_FOLDER/$TEST_NAME/run.out"
            TEARDOWN_FILE="$ARTIFACTS_FOLDER/$TEST_NAME/teardown.out"
            test_setup_wrapper "$SETUP_FILE" && test_run_wrapper "$RUN_FILE" && test_teardown_wrapper "$TEARDOWN_FILE" && save_logs "$ARTIFACTS_FOLDER"
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
