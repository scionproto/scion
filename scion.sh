#!/usr/bin/env bash


# BEGIN subcommand functions
cmd_init() {
    echo "Checking if tweetnacl has been built..."
    if [ -f lib/crypto/python-tweetnacl-20140309/build/python3.4/tweetnacl.so ] && [ -f lib/crypto/python-tweetnacl-20140309/build/python2.7/tweetnacl.so ]
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
    cd topology/
    PYTHONPATH=../ python3 generator.py $1
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
    echo "Running the network..."
    supervisor/supervisor.sh reload
    supervisor/supervisor.sh quickstart all
}

cmd_stop() {
    echo "Terminating this run of the SCION infrastructure"
    supervisor/supervisor.sh quickstop all
}

cmd_clean() {
    {
    sudo ip addr flush dev lo
    sudo ip addr add 127.0.0.1/8 dev lo
    } &> /dev/null
    echo "Clean completed. Please check the output of ip addr to confirm the addresses were correctly flushed."
}

cmd_start(){
    # placeholder function to run all init functions
    # cmd_init
    # cmd_topology
    # cmd_setup
    # cmd_run
    echo "This method has not been fully implemented. Please run init, topology, setup, and run"
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
	    $PROGRAM start
	        (not implemented) Performs all tasks (compile crypto lib, creates a topology, adds IP aliases, runs the network)
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
ARG="$2"

case $COMMAND in
    init|--init) shift;		cmd_init ;;
    topology|--topology) shift; cmd_topology $ARG;;
    setup|--setup) shift;       cmd_setup ;;
    run|--run) shift;           cmd_run ;;
    start|--start) shift;       cmd_start ;;
    stop|--stop) shift;         cmd_stop ;;
    clean|--clean) shift;       cmd_clean ;;
    help|--help) shift;         cmd_help ;;
    version|--version) shift;   cmd_version ;;
    *)          		cmd_help ;;
esac
exit 0

