#!/bin/bash

export PYTHONPATH=python/:.

EXTRA_NOSE_ARGS="-w python/ --with-xunit --xunit-file=logs/nosetests.xml"

# BEGIN subcommand functions

cmd_topology() {
    local zkclean
    echo "Shutting down supervisord: $(supervisor/supervisor.sh shutdown)"
    mkdir -p logs traces
    [ -e gen ] && rm -r gen
    [ -e gen-cache ] && rm -r gen-cache
    mkdir gen-cache
    if [ "$1" = "zkclean" ]; then
        shift
        zkclean="y"
    fi
    echo "Create topology, configuration, and execution files."
    python/topology/generator.py "$@" || exit 1
    if [ -n "$zkclean" ]; then
        echo "Deleting all Zookeeper state"
        rm -rf /run/shm/scion-zk
        tools/zkcleanslate --zk 127.0.0.1:2181
    fi
}

cmd_run() {
    if [ "$1" != "nobuild" ]; then
        echo "Compiling..."
        cmd_build || exit 1
    fi
    echo "Running the network..."
    if [ -e gen/zk_datalog_dirs.sh ]; then
        bash gen/zk_datalog_dirs.sh || exit 1
    fi
    supervisor/supervisor.sh start all
}

cmd_stop() {
    echo "Terminating this run of the SCION infrastructure"
    supervisor/supervisor.sh stop all
    find /run/shm/dispatcher /run/shm/sciond -type s -print0 | xargs -r0 rm -v
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
    nosetests3 ${EXTRA_NOSE_ARGS} "$@"
}

go_test() {
    # `make -C go` breaks if there are symlinks in $PWD
    ( cd go && make -s test )
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
    nosetests3 ${EXTRA_NOSE_ARGS} --with-cov --cov-report html "$@"
    echo
    echo "Python coverage report here: file://$PWD/python/htmlcov/index.html"
}

go_cover() {
    ( cd go && make -s coverage )
}

cmd_lint() {
    set -o pipefail
    local ret=0
    py_lint
    ret=$((ret+$?))
    go_lint
    ret=$((ret+$?))
    return $ret
}

py_lint() {
    local ret=0
    for i in python python/mininet; do
      [ -d "$i" ] || continue
      echo "Linting $i"
      local cmd="flake8"
      [ "$i" = "python/mininet" ] && cmd="python2 -m flake8"
      echo "============================================="
      ( cd "$i" && $cmd --config flake8.ini . ) | sort -t: -k1,1 -k2n,2 -k3n,3 || ((ret++))
    done
    return $ret
}

go_lint() {
    ( cd go && make -s lint )
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
        USER_OPTS=-DBYPASS_ROUTERS make -s
    else
        make -s
    fi
}

cmd_clean() {
    make -s clean
}

cmd_sciond() {
    [ -n "$1" ] || { echo "ISD-AS argument required"; exit 1; }
    # Convert the ISD-AS argument into an array, where the first element is the
    # ISD, and the second is the AS.
    IFS=- read -a ia <<< $1
    ISD=${ia[0]:?No ISD provided}
    AS=${ia[1]:?No AS provided}
    ADDR=${2:-127.${ISD}.${AS}.254}
    GENDIR=gen/ISD${ISD}/AS${AS}/endhost
    [ -d "$GENDIR" ] || { echo "Topology directory for $ISD-$AS doesn't exist: $GENDIR"; exit 1; }
    APIADDR="/run/shm/sciond/${ISD}-${AS}.sock"
    PYTHONPATH=python/:. python/bin/sciond --addr $ADDR --api-addr $APIADDR sd${ISD}-${AS} $GENDIR &
    echo "Sciond running for $ISD-$AS (pid $!)"
    wait
    exit $?
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
    start) cmd_run "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
