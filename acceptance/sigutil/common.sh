#!/bin/bash

TEST_TOPOLOGY="topology/Tiny.topo"
SRC_IA=${SRC_IA:-1-ff00:0:111}
DST_IA=${DST_IA:-1-ff00:0:112}

. acceptance/common.sh

test_setup() {
    set -e
    ./scion.sh topology zkclean -c $TEST_TOPOLOGY -d --sig -n 242.254.0.0/16
    ./scion.sh run nobuild
    ./tools/dc start 'tester*'
    sleep 10
}

test_teardown() {
    ./tools/dc down
}

print_help() {
    echo
	cat <<-_EOF
	    $PROGRAM name
	        return the name of this test
	    $PROGRAM setup
	        execute only the setup phase.
	    $PROGRAM run
	        execute only the run phase.
	    $PROGRAM teardown 
	        execute only the teardown phase.
	_EOF
}

PROGRAM=`basename "$0"`
COMMAND="$1"

do_command() {
    PROGRAM="$1"
    COMMAND="$2"
    TEST_NAME="$3"
    shift 3
    case "$COMMAND" in
        name)
            echo $TEST_NAME ;;
        setup|run|teardown)
            "test_$COMMAND" "$@" ;;
        *) print_help; exit 1 ;;
    esac
}
