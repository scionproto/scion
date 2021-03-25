#!/bin/bash

export PYTHONPATH=.

# BEGIN subcommand functions

run_silently() {
    tmpfile=$(mktemp /tmp/scion-silent.XXXXXX)
    $@ >>$tmpfile 2>&1
    if [ $? -ne 0 ]; then
        cat $tmpfile
        return 1
    fi
    return 0
}

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
        echo "Shutting down: $(./scion.sh stop)"
    fi
    supervisor/supervisor.sh shutdown
    stop_jaeger
    rm -rf traces/*
    mkdir -p logs traces gen gen-cache gen-certs
    find gen gen-cache gen-certs -mindepth 1 -maxdepth 1 -exec rm -r {} +
}

cmd_topology() {
    set -e
    cmd_topo_clean

    # Build the necessary binaries.
    bazel build //:scion-topo
    tar --overwrite -xf bazel-bin/scion-topo.tar -C bin

    echo "Create topology, configuration, and execution files."
    python/topology/generator.py "$@"
    if is_docker_be; then
        ./tools/quiet ./tools/dc run utils_chowner
    fi
}

cmd_run() {
    if [ "$1" != "nobuild" ]; then
        echo "Compiling..."
        make -s build || exit 1
        if is_docker_be; then
            echo "Build perapp images"
            bazel run -c opt //docker:prod
            echo "Build scion tester"
            bazel run //docker:test
        fi
    fi
    run_setup
    echo "Running the network..."
    if is_docker_be; then
        docker-compose -f gen/scion-dc.yml -p scion build
        docker-compose -f gen/scion-dc.yml -p scion up -d
        return 0
    fi
    # Start dispatcher first, as it is requrired by the border routers.
    ./tools/quiet ./scion.sh mstart '*dispatcher*' # for supervisor
    # Start border routers before all other services to provide connectivity.
    ./tools/quiet ./scion.sh mstart '*br*'
    ./tools/quiet ./supervisor/supervisor.sh start all
}

load_cust_keys() {
    if [ -f 'gen/load_custs.sh' ]; then
        echo "Loading customer keys..."
        ./tools/quiet ./gen/load_custs.sh
    fi
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
    run_setup
    # Run with docker-compose or supervisor
    if is_docker_be; then
        services="$(glob_docker "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        ./tools/dc scion up -d $services
    else
        supervisor/supervisor.sh mstart "$@"
    fi
}

run_setup() {
    python/integration/set_ipv6_addr.py -a
     # Create dispatcher dir or change owner
    local disp_dir="/run/shm/dispatcher"
    [ -d "$disp_dir" ] || mkdir "$disp_dir"
    [ $(stat -c "%U" "$disp_dir") == "$LOGNAME" ] || { sudo -p "Fixing ownership of $disp_dir - [sudo] password for %p: " chown $LOGNAME: "$disp_dir"; }

    run_jaeger
}

cmd_stop() {
    echo "Terminating this run of the SCION infrastructure"
    if is_docker_be; then
        ./tools/quiet ./tools/dc stop 'scion*'
    else
        ./tools/quiet ./supervisor/supervisor.sh stop all
    fi
    stop_jaeger
    if [ "$1" = "clean" ]; then
        python/integration/set_ipv6_addr.py -d
    fi
    local disp_dir="/run/shm/dispatcher"
    if [ -e "$disp_dir" ]; then
      find "$disp_dir" -xdev -mindepth 1 -print0 | xargs -r0 rm -v
    fi
}

cmd_mstop() {
    if is_docker_be; then
        services="$(glob_docker "$@")"
        [ -z "$services" ] && { echo "ERROR: No process matched for $@!"; exit 255; }
        ./tools/dc scion stop $services
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
        out=$(./tools/dc scion ps $services | tail -n +3)
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

is_supervisor() {
   [ -f gen/dispatcher/supervisord.conf ]
}

cmd_test(){
    echo "deprecated, use"
    echo "make test"
    echo "instead"
    exit 1
}

cmd_coverage(){
    set -e
    case "$1" in
        go) shift; go_cover "$@";;
        *) go_cover;;
    esac
}

go_cover() {
    ( cd go && make -s coverage )
}

cmd_lint() {
    set -o pipefail
    local ret=0
    go_lint || ret=1
    bazel_lint || ret=1
    protobuf_lint || ret=1
    md_lint || ret=1
    return $ret
}

go_lint() {
    lint_header "go"
    local TMPDIR=$(mktemp -d /tmp/scion-lint.XXXXXXX)
    local LOCAL_DIRS="$(find go/* -maxdepth 0 -type d | grep -v vendor)"
    # Find go files to lint, excluding generated code. For linelen and misspell.
    find go acceptance -type f -iname '*.go' \
      -a '!' -ipath '*.pb.go' \
      -a '!' -ipath '*.gen.go' \
      -a '!' -ipath 'go/proto/*.capnp.go' \
      -a '!' -ipath '*mock_*' > $TMPDIR/gofiles.list
    lint_step "Building lint tools"

    run_silently bazel build //:lint || return 1
    tar -xf bazel-bin/lint.tar -C $TMPDIR || return 1
    local ret=0
    lint_step "gofmt"
    # TODO(sustrik): At the moment there are no bazel rules for gofmt.
    # See: https://github.com/bazelbuild/rules_go/issues/511
    # Instead we'll just run the commands from Go SDK directly.
    GOSDK=$(bazel info output_base 2>/dev/null)/external/go_sdk/bin
    out=$($GOSDK/gofmt -d -s $LOCAL_DIRS ./acceptance);
    if [ -n "$out" ]; then echo "$out"; ret=1; fi
    lint_step "linelen (lll)"
    out=$($TMPDIR/lll -w 4 -l 100 --files -e '`comment:"|`ini:"|https?:|`sql:"|gorm:"|`json:"|`yaml:' < $TMPDIR/gofiles.list)
    if [ -n "$out" ]; then echo "$out"; ret=1; fi
    lint_step "misspell"
    xargs -a $TMPDIR/gofiles.list $TMPDIR/misspell -error || ret=1
    lint_step "bazel"
    run_silently make gazelle GAZELLE_MODE=diff || ret=1
    bazel test --config lint || ret=1
    # Clean up the binaries
    rm -rf $TMPDIR
    return $ret
}

protobuf_lint() {
    lint_header "protobuf"
    local TMPDIR=$(mktemp -d /tmp/scion-lint.XXXXXXX)
    run_silently bazel build //:lint || return 1
    tar -xf bazel-bin/lint.tar -C $TMPDIR || return 1
    local ret=0
    lint_step "check files"
    $TMPDIR/buf check lint || return 1
}

bazel_lint() {
    lint_header "bazel"
    local ret=0
    run_silently bazel run //:buildifier_check || ret=1
    if [ $ret -ne 0 ]; then
        printf "\nto fix run:\nbazel run //:buildifier\n"
    fi
    return $ret
}

md_lint() {
    lint_header "markdown"
    lint_step "mdlint"
    ./tools/mdlint
}

lint_header() {
    printf "\nlint $1\n==============\n"
}

lint_step() {
    echo "======> $1"
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
    make -s
}

cmd_clean() {
    make -s clean
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
	cmd_version
	echo
	cat <<-_EOF
	Usage:
	    $PROGRAM topology
	        Create topology, configuration, and execution files.
	        All arguments or options are passed to topology/generator.py
	    $PROGRAM run [nobuild]
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
	    $PROGRAM test
	        Run all unit tests.
	    $PROGRAM coverage
	        Create a html report with unit test code coverage.
	    $PROGRAM help
	        Show this text.
	    $PROGRAM version
	        Show version information.
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
    coverage|help|lint|run|mstart|mstatus|mstop|stop|status|test|topology|version|build|clean|traces|stop_traces|topo_clean|bazel_remote)
        "cmd_$COMMAND" "$@" ;;
    start) cmd_run "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
