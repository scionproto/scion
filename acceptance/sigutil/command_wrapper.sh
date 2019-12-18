#!/bin/bash

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
