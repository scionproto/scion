#!/bin/bash

TEST_TOPOLOGY=${TEST_TOPOLOGY:-topology/tiny4.topo}
SRC_IA=${SRC_IA:-1-ff00:0:111}
DST_IA=${DST_IA:-1-ff00:0:112}

. acceptance/common.sh

test_setup() {
    set -e
    ./scion.sh topology -c $TEST_TOPOLOGY -d --sig -n 242.254.0.0/16
    ./scion.sh run nobuild
    ./tools/dc start 'tester*'
    sleep 20
    docker_status
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

reload_sig() {
    log "Reloading SIG config for $1"
    ./tools/dc scion kill -s SIGHUP scion_sig_"$1" || echo "sending SIGHUP failed"
    # Wait till the new config takes effect.
    sleep 3
}
