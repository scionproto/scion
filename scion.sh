#!/usr/bin/env bash


# BEGIN subcommand functions
cmd_init() {
    echo "Compile the SCION crypto library."
    cd lib/crypto/python-tweetnacl-20140309/
    sh do
}

cmd_topology() {
    echo "Create topology, configuration, and execution files."
    mkdir -p logs
    cd topology/
    PYTHONPATH=../ python3 generator.py
}

cmd_setup() {
    echo "Add IP aliases for ISDs and ADs."
    for d in topology/ISD*; do
        for f in $d/setup/*; do
            sudo bash $f
        done
    done
}

cmd_run() {
    echo "Run network."
    cd infrastructure/
    for d in ../topology/ISD*; do
        for f in $d/run/*; do
            echo "running $f"
            bash $f
        done
    done
}

cmd_stop() {
    echo "Terminating this run of the SCION infrastructure"
    sudo killall screen
}

cmd_clean() {
    {
    sudo ip addr flush dev lo
    sudo ip addr add 127.0.0.1/8 dev lo
    } &> /dev/null
    echo "Check the output of ip addr to confirm the addresses were correctly flushed."
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
	    $PROGRAM setup
	    	Add IP aliases for ISDs and ADs.
	    $PROGRAM run
	        Run network.
	    $PROGRAM stop
	        Terminate this run of the SCION infrastructure.
	    $PROGRAM clean
	        Flush all the IP aliases of lo. 
	    $PROGRAM help
	        Show this text.
	    $PROGRAM version
	        Show version information.
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"

case "$1" in
    init|--init) shift;		cmd_init ;;
    topology|--topology) shift; cmd_topology ;;
    setup|--setup) shift;       cmd_setup ;;
    run|--run) shift;           cmd_run ;;
    stop|--stop) shift;         cmd_stop ;;
    clean|--clean) shift;       cmd_clean ;;
    help|--help) shift;         cmd_help ;;
    version|--version) shift;   cmd_version ;;
    *)          		cmd_help ;;
esac
exit 0