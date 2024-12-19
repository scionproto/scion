#!/bin/bash

# BEGIN subcommand functions

traces_name() {
    echo "jaeger_read_badger_traces"
}

cmd_start() {
    set -e
    local trace_dir=${1:-"$(readlink -e .)/traces"}
    local port=16687
    local name=$(traces_name)
    cmd_stop
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
    echo "Jaeger UI: http://localhost:$port"
}

cmd_stop() {
    local name=$(traces_name)
    docker stop "$name" || true
    docker rm "$name" || true
}

cmd_help() {
    cat <<-_EOF
	$PROGRAM is a helper script to start and stop a stand-alone jaeger UI.
	It does not initiate any jaeger trace collection and shows whatever
	traces happen to be in the given directory; not necessarily scion traces.

	If you mean to initiate SCION jaeger traces (and look at them), use
	scion.sh start-traces instead.
	
	Usage:
	    $PROGRAM start
	        Serve jaeger traces from the default folder: traces/.
	    $PROGRAM start [folder]
	        Serve jaeger traces from the specified folder.
	    $PROGRAM stop
	        Stop the jaeger container started with start command.
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift

case "$COMMAND" in
    help|start|stop)
        "cmd_$COMMAND" "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
