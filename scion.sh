#!/bin/bash

# BEGIN subcommand functions

cmd_bazel_remote() {
    mkdir -p "$HOME/.cache/bazel/remote"
    uid=$(id -u)
    gid=$(id -g)
    USER_ID="$uid" GROUP_ID="$gid" docker-compose -f bazel-remote.yml -p bazel_remote up -d
}

cmd_topo_clean() {
    set -e
    if is_docker_be; then
        echo "Shutting down dockerized topology..."
        ./tools/quiet ./tools/dc down || true
    else
        ./tools/quiet tools/supervisor.sh shutdown
        run_teardown
    fi
    stop_jaeger
    rm -rf traces/*
    mkdir -p logs traces gen gen-cache gen-certs
    find gen gen-cache gen-certs -mindepth 1 -maxdepth 1 -exec rm -r {} +
}

cmd_topology() {
    set -e
    cmd_topo_clean

    echo "Create topology, configuration, and execution files."
    tools/topogen.py "$@"
    if is_docker_be; then
        ./tools/quiet ./tools/dc run utils_chowner
    fi
}

cmd_topodot() {
    ./tools/topodot.py "$@"
}

cmd_run() {
    run_jaeger
    echo "Running the network..."
    if is_docker_be; then
        docker-compose -f gen/scion-dc.yml -p scion up -d
        return 0
    else
        run_setup
        ./tools/quiet tools/supervisor.sh start all
    fi
}

cmd_sciond-addr() {
    jq -r 'to_entries |
           map(select(.key | match("'"$1"'";"i"))) |
           if length != 1 then error("No unique match for '"$1"'") else .[0] end |
           "[\(.value)]:30255"' gen/sciond_addresses.json
}

run_jaeger() {
    if [ ! -f "gen/jaeger-dc.yml" ]; then
        return
    fi
    echo "Running jaeger..."
    ./tools/quiet ./tools/dc jaeger up -d
}

stop_jaeger() {
    if [ ! -f "gen/jaeger-dc.yml" ]; then
        return
    fi
    echo "Stopping jaeger..."
    ./tools/quiet ./tools/dc jaeger down -v
}

cmd_mstart() {
    # Run with docker-compose or supervisor
    if is_docker_be; then
        services="$(glob_docker "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        ./tools/dc scion up -d $services
    else
        run_setup
        tools/supervisor.sh mstart "$@"
    fi
}

run_setup() {
    tools/set_ipv6_addr.py -a
    # Ensure base dir for dispatcher socket exists; on ubuntu this symbolic link to /dev/shm always exists.
    if [ ! -d /run/shm/ ]; then
      sudo ln -s /dev/shm /run/shm;
    fi
     # Create dispatcher dir or change owner
    local disp_dir="/run/shm/dispatcher"
    [ -d "$disp_dir" ] || mkdir "$disp_dir"
    [ $(stat -c "%U" "$disp_dir") == "$LOGNAME" ] || { sudo -p "Fixing ownership of $disp_dir - [sudo] password for %p: " chown $LOGNAME: "$disp_dir"; }
}

run_teardown() {
    tools/set_ipv6_addr.py -d
    local disp_dir="/run/shm/dispatcher"
    if [ -e "$disp_dir" ]; then
      find "$disp_dir" -xdev -mindepth 1 -print0 | xargs -r0 rm -v
    fi
}

cmd_stop() {
    echo "Terminating this run of the SCION infrastructure"
    if is_docker_be; then
        ./tools/quiet ./tools/dc stop 'scion*'
    else
        ./tools/quiet tools/supervisor.sh stop all
        run_teardown
    fi
    stop_jaeger
}

cmd_mstop() {
    if is_docker_be; then
        services="$(glob_docker "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        ./tools/dc scion stop $services
    else
        tools/supervisor.sh mstop "$@"
    fi
}

cmd_status() {
    cmd_mstatus '*'
}

cmd_mstatus() {
    if is_docker_be; then
        services="$(glob_docker "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        out=$(./tools/dc scion ps $services | tail -n +3)
        rscount=$(echo "$out" | grep '\<Up\>' | wc -l) # Number of running services
        tscount=$(echo "$services" | wc -w) # Number of all globed services
        echo "$out" | grep -v '\<Up\>'
        [ $rscount -eq $tscount ]
    else
        if [ $# -ne 0 ]; then
            services="$(glob_supervisor "$@")"
            [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
            tools/supervisor.sh status "$services" | grep -v RUNNING
        else
            tools/supervisor.sh status | grep -v RUNNING
        fi
        [ $? -eq 1 ]
    fi
    # If all tasks are running, then return 0. Else return 1.
    return
}

glob_supervisor() {
    [ $# -ge 1 ] || set -- '*'
    matches=
    for proc in $(tools/supervisor.sh status | awk '{ print $1 }'); do
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
    for proc in $(./tools/dc scion config --services); do
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

traces_name() {
    local name=jaeger_read_badger_traces
    echo "$name"
}

cmd_traces() {
    set -e
    local trace_dir=${1:-"$(readlink -e .)/traces"}
    local port=16687
    local name=$(traces_name)
    cmd_stop_traces
    docker run -d --name "$name" \
        -u "$(id -u):$(id -g)" \
        -e SPAN_STORAGE_TYPE=badger \
        -e BADGER_EPHEMERAL=false \
        -e BADGER_DIRECTORY_VALUE=/badger/data \
        -e BADGER_DIRECTORY_KEY=/badger/key \
        -v "$trace_dir:/badger" \
        -p "$port":16686 \
        jaegertracing/all-in-one:1.22.0
    sleep 3
    x-www-browser "http://localhost:$port"
}

cmd_stop_traces() {
    local name=$(traces_name)
    docker stop "$name" || true
    docker rm "$name" || true
}

cmd_help() {
	cat <<-_EOF
	SCION

	$PROGRAM runs a SCION network locally for development and testing purposes.
	Two options for process control systems are supported to run the SCION
	services.
	  - supervisord (default)
	  - docker-compose
	This can be selected when initially creating the configuration with the
	topology subcommand.

	Usage:
	    $PROGRAM topology [-d] [-c TOPOFILE]
	        Create topology, configuration, and execution files.
	        All arguments or options are passed to tools/topogen.py
	    $PROGRAM run
	        Run network.
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
	    $PROGRAM sciond-addr ISD-AS
	        Return the address for the scion daemon for the matching ISD-AS by
	        consulting gen/sciond_addresses.json.
	        The ISD-AS parameter can be a substring of the full ISD-AS (e.g. last
	        three digits), as long as there is a unique match.
	    $PROGRAM topodot [-s|--show] TOPOFILE
	        Draw a graphviz graph of a *.topo topology configuration file.
	    $PROGRAM help
	        Show this text.
	    $PROGRAM traces [folder]
	        Serve jaeger traces from the specified folder (default: traces/)
	    $PROGRAM stop_traces
	        Stop the jaeger container started during the traces command
	    $PROGRAM bazel_remote
	        Starts the bazel remote.
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift

case "$COMMAND" in
    help|run|mstart|mstatus|mstop|stop|status|topology|sciond-addr|traces|stop_traces|topo_clean|topodot|bazel_remote)
        "cmd_$COMMAND" "$@" ;;
    start) cmd_run "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
