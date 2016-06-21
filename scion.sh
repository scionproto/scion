#!/usr/bin/env bash

export PYTHONPATH=.

# BEGIN subcommand functions

cmd_topology() {
    local zkclean
    if type -p supervisorctl &>/dev/null; then
        echo "Shutting down supervisord: $(supervisor/supervisor.sh shutdown)"
    fi
    mkdir -p logs traces
    [ -e gen ] && rm -r gen
    if [ "$1" = "zkclean" ]; then
        shift
        zkclean="y"
    fi
    echo "Create topology, configuration, and execution files."
    topology/generator.py "$@"
    if [ -n "$zkclean" ]; then
        echo "Deleting all Zookeeper state"
        rm -rf /run/shm/scion-zk
        tools/zkcleanslate --zk 127.0.0.1:2181
    fi
}

cmd_run() {
    if [ "$1" != "nobuild" ]; then
        echo "Compiling C code..."
        cmd_build || exit 1
    fi
    echo "Running the network..."
    if [ -e gen/zk_datalog_dirs.sh ]; then
        bash gen/zk_datalog_dirs.sh || exit 1
    fi
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
    for i in . sub/web; do
      [ -d "$i" ] || continue
      echo "Linting $i"
      echo "============================================="
      (cd "$i" && flake8 --config flake8.ini . ) | sort -t: -k1,1 -k2n,2 -k3n,3
    done
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
        USER_OPTS=-DBYPASS_ROUTERS make -s all install
    else
        make -s all install
    fi
}

cmd_clean() {
    make -s clean
}

SOCKDIR=endhost/ssp

cmd_sock_cli() {
    if [ $# -eq 2 ]
    then
        GENDIR=gen/ISD${1}/AS${2}/endhost
        ADDR="127.${1}.${2}.254"
        ISD=${1}
        AS=${2}
    else
        GENDIR=gen/ISD1/AS19/endhost
        ADDR="127.1.19.254"
        ISD="1"
        AS="19"
    fi
    # FIXME(aznair): Will become ISD_AS.sock in later PR
    APIADDR="/run/shm/sciond/${ISD}-${AS}.sock"
    PYTHONPATH=.
    bin/sciond --addr $ADDR --api-addr $APIADDR sspclient $GENDIR
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
        ISD=${1}
        AS=${2}
    else
        GENDIR=gen/ISD2/AS26/endhost
        ADDR="127.2.26.254"
        ISD="2"
        AS="26"
    fi
    # FIXME(aznair): Will become ISD_AS.sock in later PR
    APIADDR="/run/shm/sciond/${ISD}-${AS}.sock"
    PYTHONPATH=.
    bin/sciond --addr $ADDR --api-addr $APIADDR sspserver $GENDIR
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
