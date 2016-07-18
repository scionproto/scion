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
    set -e
    case "$1" in
        py) shift; py_test "$@";;
        go) shift; go_test "$@";;
        *) py_test; go_test;;
    esac
}

py_test() {
    nosetests "$@"
}

go_test() {
    go test "$@" ./go/...
}

cmd_coverage(){
    set -e
    case "$1" in
        py) shift; py_cover "$@";;
        go) shift; go_cover "$@";;
        *) py_cover;
           echo "============================================="
           go_cover;;
    esac
}

py_cover() {
    nosetests --with-cov --cov-report html "$@"
    echo
    echo "Python coverage report here: file://$PWD/htmlcov/index.html"
}

go_cover() {
    set -o pipefail
    gocov test ./go/... | gocov-html > go/gocover.html
    echo
    echo "Go coverage report here: file://$PWD/go/gocover.html"
}

cmd_lint() {
    set -o pipefail
    local ret=0
    for i in . sub/web; do
      [ -d "$i" ] || continue
      echo "Linting $i"
      echo "============================================="
      ( cd "$i" && flake8 --config flake8.ini . ) | sort -t: -k1,1 -k2n,2 -k3n,3 || ((ret++))
    done
    return $ret
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

cmd_sciond() {
    ISD=${1:?No ISD provided}
    AS=${2:?No AS provided}
    ADDR=${3:-127.${ISD}.${AS}.254}
    GENDIR=gen/ISD${ISD}/AS${AS}/endhost
    # FIXME(aznair): Will become ISD_AS.sock in later PR
    APIADDR="/run/shm/sciond/${ISD}-${AS}.sock"
    PYTHONPATH=.
    exec bin/sciond --addr $ADDR --api-addr $APIADDR sd-${ISD}-${AS} $GENDIR
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
	    $PROGRAM sciond ISD AS [ADDR]
	        Start sciond with provided ISD and AS parameters. A third optional
	        parameter is the address to bind when not running on localhost.
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
    coverage|help|lint|run|stop|status|test|topology|version|build|clean|sciond)
        "cmd_$COMMAND" "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
