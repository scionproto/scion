#!/usr/bin/env bash

export PYTHONPATH=.

# BEGIN subcommand functions

cmd_topology() {
    if type -p supervisorctl &>/dev/null; then
        echo "Shutting down supervisord: $(supervisor/supervisor.sh shutdown)"
    fi
    mkdir -p logs traces
    [ -e gen ] && rm -r gen
    if [ "$1" = "zkclean" ]; then
        shift
        echo "Deleting all Zookeeper state"
        tools/zkcleanslate
    fi
    echo "Create topology, configuration, and execution files."
    topology/generator.py "$@"
}

cmd_run() {
    if [ "$1" != "nobuild" ]; then
        echo "Compiling C code..."
        cmd_build || exit 1
    fi
    echo "Running the network..."
    bash gen/zk_datalog_dirs.sh || exit 1
    supervisor/supervisor.sh quickstart dispatcher:dispatcher
    supervisor/supervisor.sh quickstart all
}

cmd_stop() {
    echo "Terminating this run of the SCION infrastructure"
    supervisor/supervisor.sh quickstop all
}

cmd_status() {
    supervisor/supervisor.sh status | grep -v RUNNING
    # If all tasks are running, then return 0. Else return 1.
    [ $? -eq 1 ]
    return
}

cmd_test(){
    nosetests "$@"
}

cmd_coverage(){
    set -e
    nosetests --with-cov --cov-report html "$@"
    coverage report
    echo "Coverage report here: file://$PWD/htmlcov/index.html"
}

cmd_lint() {
    set -o pipefail
    flake8 --config flake8.ini "${@:-.}" | sort -t: -k1,1 -k2n,2 -k3n,3
}

cmd_version() {
	cat <<-_EOF
	============================================
	=                  SCION                   =
	=   https://github.com/netsec-ethz/scion   =
	============================================
	_EOF
}

cmd_build() {
    if [ "$1" == "bypass" ]; then
        USER_OPTS=-DBYPASS_ROUTERS make all install
    else
        make all install
    fi
}

cmd_clean() {
    make clean
}

SOCKDIR=endhost/ssp

cmd_sock_cli() {
    if [ $# -eq 2 ]
    then
        GENDIR=gen/ISD${1}/AS${2}/endhost
        ADDR="127.${1}.${2}.254"
    else
        GENDIR=gen/ISD1/AS19/endhost
        ADDR="127.1.19.254"
    fi
    # FIXME(aznair): Will become ISD_AS.sock in later PR
    APIADDR="/run/shm/sciond/client"
    PYTHONPATH=.
    python3 endhost/dummy.py $GENDIR $ADDR $APIADDR client
}

cmd_run_cli() {
    export LD_LIBRARY_PATH=`pwd`/endhost/ssp
    $SOCKDIR/test/client
}

cmd_sock_ser() {
    if [ $# -eq 2 ]
    then
        GENDIR=gen/ISD${1}/AS${2}/endhost
        ADDR="127.${1}.${2}.254"
    else
        GENDIR=gen/ISD2/AS26/endhost
        ADDR="127.2.26.254"
    fi
    # FIXME(aznair): Will become ISD_AS.sock in later PR
    APIADDR="/run/shm/sciond/server"
    PYTHONPATH=.
    python3 endhost/dummy.py $GENDIR $ADDR $APIADDR server
}

cmd_run_ser() {
    export LD_LIBRARY_PATH=`pwd`/endhost/ssp
    $SOCKDIR/test/server
}

cmd_help() {
	cmd_version
	echo
	cat <<-_EOF
	Usage:
	    $PROGRAM topology [zkclean]
	        Create topology, configuration, and execution files. With the
	        'zkclean' option, also reset all local Zookeeper state. Another
	        other arguments or options are passed to topology/generator.py
	    $PROGRAM run
	        Run network.
	    $PROGRAM stop
	        Terminate this run of the SCION infrastructure.
	    $PROGRAM status
	        Show all non-running tasks.
	    $PROGRAM test
	        Run all unit tests.
	    $PROGRAM coverage
	        Create a html report with unit test code coverage.
	    $PROGRAM help
	        Show this text.
	    $PROGRAM version
	        Show version information.
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift

case "$COMMAND" in
    coverage|help|lint|run|stop|status|test|topology|version|\
    sock_cli|sock_ser|build|clean|run_cli|run_ser)
        "cmd_$COMMAND" "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
