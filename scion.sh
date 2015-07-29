#!/usr/bin/env bash

# BEGIN subcommand functions

cmd_init() {
    echo "Checking if tweetnacl has been built..."
    if [ -f lib/crypto/python-tweetnacl-20140309/build/python3.4/tweetnacl.so ]
    then
        echo "tweetnacl exists."
    else
        echo "tweetnacl.so does not exist. Compiling..."
        cd lib/crypto/python-tweetnacl-20140309/
        sh do
    fi
}

cmd_topology() {
    echo "Create topology, configuration, and execution files."
    mkdir -p logs traces
    PYTHONPATH=./ python3 topology/generator.py "$@"
}

cmd_run() {
    echo "Running the network..."
    supervisor/supervisor.sh reload
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
    PYTHONPATH=. nosetests -w test "$@"
}

cmd_coverage(){
    set -e
    PYTHONPATH=. nosetests --with-cov -w test "$@"
    coverage html --omit 'external/*'
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

cmd_help() {
	cmd_version
	echo
	cat <<-_EOF
	Usage:
	    $PROGRAM init
	        Compile the SCION crypto library.
	    $PROGRAM topology
	        Create topology, configuration, and execution files.
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
    coverage|help|init|lint|run|stop|status|test|topology|version)
        "cmd_$COMMAND" "$@" ;;
    *)  cmd_help ;;
esac
