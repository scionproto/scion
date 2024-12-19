#!/bin/bash

# BEGIN subcommand functions

cmd_bazel-remote() {
    mkdir -p "$HOME/.cache/bazel/remote"
    uid=$(id -u)
    gid=$(id -g)
    USER_ID="$uid" GROUP_ID="$gid" docker compose -f bazel-remote.yml up -d
}

cmd_topo-clean() {
    set -e
    stop_scion || true
    cmd_stop-monitoring || true
    rm -rf traces/*
    mkdir -p logs traces gen gen-cache gen-certs
    find gen gen-cache gen-certs -mindepth 1 -maxdepth 1 -exec rm -r {} +
}

cmd_topology() {
    set -e
    cmd_topo-clean

    echo "Create topology, configuration, and execution files."
    ./bin/topogen "$@"
}

cmd_topodot() {
    ./bin/topodot "$@"
}

start_scion() {
    echo "Running the network..."
    if is_docker_be; then
        docker compose -f gen/scion-dc.yml up -d
        return 0
    else
        run_setup
        ./tools/quiet tools/supervisor.sh start all
    fi
}

cmd_start() {
    start_scion
    echo "Note that jaeger is no longer started automatically."
    echo "To run jaeger and prometheus, use $PROGRAM start-monitoring."

}

cmd_sciond-addr() {
    jq -r 'to_entries |
           map(select(.key | match("'"$1"'";"i"))) |
           if length != 1 then error("No unique match for '"$1"'") else .[0] end |
           "[\(.value)]:30255"' gen/sciond_addresses.json
}

cmd_start-monitoring() {
    if [ ! -f "gen/monitoring-dc.yml" ]; then
        return
    fi
    echo "Running monitoring..."
    echo "Jaeger UI: http://localhost:16686"
    echo "Prometheus UI: http://localhost:9090"
    ./tools/quiet ./tools/dc monitoring up -d
}

cmd_stop-monitoring() {
    if [ ! -f "gen/monitoring-dc.yml" ]; then
        return
    fi
    echo "Stopping monitoring..."
    ./tools/quiet ./tools/dc monitoring down -v
}

cmd_mstart() {
    # Run with docker compose or supervisor
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
}

run_teardown() {
    tools/set_ipv6_addr.py -d
}

stop_scion() {
    echo "Terminating this run of the SCION infrastructure"
    if is_docker_be; then
        ./tools/quiet ./tools/dc down
    else
        ./tools/quiet tools/supervisor.sh stop all # blocks until child processes are stopped
        ./tools/quiet tools/supervisor.sh shutdown # shutdown does not block, but as children are already stopped, actual shutdown will be prompt too.
        run_teardown
    fi
}

cmd_stop() {
    stop_scion
    echo "Note that jaeger is no longer stopped automatically."
    echo "To stop jaeger and prometheus, use $PROGRAM stop-monitoring."
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
    rscount=0
    tscount=0
    if is_docker_be; then
        services="$(glob_docker "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        rscount=$(./tools/dc scion ps --status=running --format "{{.Name}}" $services | wc -l)
        tscount=$(echo "$services" | wc -w) # Number of all globed services
        ./tools/dc scion ps -a --format "table {{.Name}}\t{{upper .State}}\tuptime {{.RunningFor}}" $services | sed "s/ ago//" | tail -n+2
    else
        services="$(glob_supervisor "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        rscount=$(./tools/supervisor.sh status "$services" | grep RUNNIN | wc -l)
        tscount=$(echo "$services" | wc -w) # Number of all globed services
        tools/supervisor.sh status "$services"
    fi
    # If all tasks are running, then return 0. Else return 1.
    [ $rscount -eq $tscount ]
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

cmd_help() {
    cat <<-_EOF
	SCION

	$PROGRAM runs a SCION network locally for development and testing purposes.
	Two options for process control systems are supported to run the SCION
	services.
	  - supervisord (default)
	  - docker compose
	This can be selected when initially creating the configuration with the
	topology subcommand.

	Usage:
	    $PROGRAM topology [-d] [-c TOPOFILE]
	        Create topology, configuration, and execution files.
	        All arguments or options are passed to tools/topogen.py
	    $PROGRAM run
	        Run network.
	    $PROGRAM mstart PROCESS
	        Start multiple processes.
	    $PROGRAM stop
	        Terminate this run of the SCION infrastructure.
	    $PROGRAM mstop PROCESS
	        Stop multiple processes.
	    $PROGRAM start-monitoring
	        Run the monitoring infrastructure.
	    $PROGRAM stop-monitoring
	        Terminate this run of the monitoring infrastructure.
	    $PROGRAM status
	        Show all non-running tasks.
	    $PROGRAM mstatus PROCESS
	        Show status of provided processes.
	    $PROGRAM sciond-addr ISD-AS
	        Return the address for the scion daemon for the matching ISD-AS by
	        consulting gen/sciond_addresses.json.
	        The ISD-AS parameter can be a substring of the full ISD-AS (e.g. last
	        three digits), as long as there is a unique match.
	    $PROGRAM topodot [-s|--show] TOPOFILE
	        Draw a graphviz graph of a *.topo topology configuration file.
	    $PROGRAM help
	        Show this text.
	    $PROGRAM bazel-remote
	        Starts the bazel remote.
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift

case "$COMMAND" in
    help|start|start-monitoring|mstart|mstatus|mstop|stop|stop-monitoring|status|topology|sciond-addr|topo-clean|topodot|bazel-remote)
        "cmd_$COMMAND" "$@" ;;
    run) cmd_start "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
