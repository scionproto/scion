#!/bin/bash

export PYTHONPATH=python/:.

EXTRA_NOSE_ARGS="-w python/ --with-xunit --xunit-file=logs/nosetests.xml"

# BEGIN subcommand functions

cmd_topology() {
    set -e
    local zkclean
    if is_docker_be; then
        echo "Shutting down dockerized topology..."
        ./tools/quiet ./tools/dc down
    else
        echo "Shutting down: $(./scion.sh stop)"
    fi
    supervisor/supervisor.sh shutdown
    mkdir -p logs traces gen gen-cache
    find gen gen-cache -mindepth 1 -maxdepth 1 -exec rm -r {} +
    if [ "$1" = "zkclean" ]; then
        shift
        zkclean="y"
    fi
    echo "Create topology, configuration, and execution files."
    is_running_in_docker && set -- "$@" --in-docker
    python/topology/generator.py "$@"
    if is_docker_be; then
        ./tools/quiet ./tools/dc run utils_chowner
    fi
    run_zk "$zkclean"
    if [ ! -e "gen-certs/tls.pem" -o ! -e "gen-certs/tls.key" ]; then
        local old=$(umask)
        echo "Generating TLS cert"
        mkdir -p "gen-certs"
        umask 0177
        openssl genrsa -out "gen-certs/tls.key" 2048
        umask "$old"
        openssl req -new -x509 -key "gen-certs/tls.key" -out "gen-certs/tls.pem" -days 3650 -subj /CN=scion_def_srv
    fi
}

cmd_run() {
    if [ "$1" != "nobuild" ]; then
        echo "Compiling..."
        cmd_build || exit 1
        if is_docker_be; then
            echo "Build scion_base image"
            ./tools/quiet ./docker.sh base
            echo "Build scion image"
            ./tools/quiet ./docker.sh build
            echo "Build perapp images"
            ./tools/quiet make -C docker/perapp
        fi
    fi
    run_setup
    echo "Running the network..."
    # Run with docker-compose or supervisor
    if is_docker_be; then
        ./tools/quiet ./tools/dc start 'scion*'
    else
        ./tools/quiet ./supervisor/supervisor.sh start all
    fi
}

run_zk() {
    echo "Running zookeeper..."
    ./tools/quiet ./tools/dc zk up -d
    if [ -n "$1" ]; then
        echo "Deleting all Zookeeper state"
        # Wait some time, such that zookeeper accepts connections again after startup
        sleep 3
        local addr="127.0.0.1:2181"
        if is_running_in_docker; then
            addr="${DOCKER0:-172.17.0.1}:2182"
        elif is_docker; then
            addr="$(./tools/docker-ip):2181"
        fi
        tools/zkcleanslate --zk "$addr"
    fi
}

cmd_mstart() {
    run_setup
    # Run with docker-compose or supervisor
    if is_docker_be; then
        services="$(glob_docker "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        ./tools/dc dc up -d $services
    else
        supervisor/supervisor.sh mstart "$@"
    fi
}

run_setup() {
    [ -n "$CIRCLECI" ] || python/integration/set_ipv6_addr.py -a
     # Create dispatcher and sciond dirs or change owner
    local disp_dir="/run/shm/dispatcher"
    [ -d "$disp_dir" ] || mkdir "$disp_dir"
    [ $(stat -c "%U" "$disp_dir") == "$LOGNAME" ] || { sudo -p "Fixing ownership of $disp_dir - [sudo] password for %p: " chown $LOGNAME: "$disp_dir"; }
    local sciond_dir="/run/shm/sciond"
    [ -d "$sciond_dir" ] || mkdir "$sciond_dir"
    [ $(stat -c "%U" "$sciond_dir") == "$LOGNAME" ] || { sudo -p "Fixing ownership of $sciond_dir - [sudo] password for %p: " chown $LOGNAME: "$sciond_dir"; }
    # Make sure zookeeper is running
    run_zk
}

cmd_stop() {
    echo "Terminating this run of the SCION infrastructure"
    if is_docker_be; then
        ./tools/quiet ./tools/dc stop 'scion*'
    else
        ./tools/quiet ./supervisor/supervisor.sh stop all
    fi
    if [ "$1" = "clean" ]; then
        python/integration/set_ipv6_addr.py -d
    fi
    for i in /run/shm/{dispatcher,sciond}/; do
        if [ -e "$i" ]; then
            find "$i" -xdev -mindepth 1 -print0 | xargs -r0 rm -v
        fi
    done
}

cmd_mstop() {
    if is_docker_be; then
        services="$(glob_docker "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        ./tools/dc dc stop $services
    else
        supervisor/supervisor.sh mstop "$@"
    fi
}

cmd_status() {
    cmd_mstatus '*'
}

cmd_mstatus() {
    if is_docker_be; then
        services="$(glob_docker "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        out=$(./tools/dc dc ps $services | tail -n +3)
        rscount=$(echo "$out" | grep '\<Up\>' | wc -l) # Number of running services
        tscount=$(echo "$services" | wc -w) # Number of all globed services
        echo "$out" | grep -v '\<Up\>'
        [ $rscount -eq $tscount ]
    else
        if [ $# -ne 0 ]; then
            services="$(glob_supervisor "$@")"
            [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
            supervisor/supervisor.sh status "$services" | grep -v RUNNING
        else
            supervisor/supervisor.sh status | grep -v RUNNING
        fi
        [ $? -eq 1 ]
    fi
    # If all tasks are running, then return 0. Else return 1.
    return
}

glob_supervisor() {
    [ $# -ge 1 ] || set -- '*'
    matches=
    for proc in $(supervisor/supervisor.sh status | awk '{ print $1 }'); do
        for spec in "$@"; do
            if glob_match $proc "$spec"; then
                matches="$matches $proc"
                break
            fi
        done
    done
    echo $matches
}

glob_docker() {
    [ $# -ge 1 ] || set -- '*'
    matches=
    for proc in $(./tools/dc dc config --services); do
        for spec in "$@"; do
            if glob_match $proc "scion_$spec"; then
                matches="$matches $proc"
                break
            fi
        done
    done
    echo $matches
}

glob_match() {
    # If $1 is matched by $2, return true
    case "$1" in
        $2) return 0;;
    esac
    return 1
}

is_docker_be() {
    [ -f gen/scion-dc.yml ]
}

is_supervisor() {
   [ -f gen/dispatcher/supervisord.conf ]
}

is_running_in_docker() {
    cut -d: -f 3 /proc/1/cgroup | grep -q '^/docker/'
}

cmd_test(){
    local ret=0
    case "$1" in
        py) shift; py_test "$@"; ret=$((ret+$?));;
        go) shift; go_test "$@"; ret=$((ret+$?));;
        *) py_test; ret=$((ret+$?)); go_test; ret=$((ret+$?));;
    esac
    return $ret
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
    for i in python; do
      [ -d "$i" ] || continue
      echo "Linting $i"
      local cmd="flake8"
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
	=   https://github.com/scionproto/scion   =
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
    ADDR=${2:-127.0.0.1}
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
	    $PROGRAM sciond ISD-AS [ADDR]
	        Start sciond with provided ISD and AS parameters, and bind to ADDR.
	        ISD-AS must be in file format (e.g., 1-ff00_0_133). If ADDR is not
	        supplied, sciond will bind to 127.0.0.1.
	    $PROGRAM mstart PROCESS
	        Start multiple processes
	    $PROGRAM stop
	        Terminate this run of the SCION infrastructure.
	    $PROGRAM mstop PROCESS
	        Stop multiple processes
	    $PROGRAM status
	        Show all non-running tasks.
	    $PROGRAM mstatus PROCESS
	        Show status of provided processes
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
    coverage|help|lint|run|mstart|mstatus|mstop|stop|status|test|topology|version|build|clean|sciond)
        "cmd_$COMMAND" "$@" ;;
    start) cmd_run "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
