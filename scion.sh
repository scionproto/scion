#!/bin/bash

export PYTHONPATH=python/:.

EXTRA_NOSE_ARGS="-w python/ --with-xunit --xunit-file=logs/nosetests.xml"

# BEGIN subcommand functions

cmd_topo_clean() {
    set -e
    if is_docker_be; then
        echo "Shutting down dockerized topology..."
        ./tools/quiet ./tools/dc down
    else
        echo "Shutting down: $(./scion.sh stop)"
    fi
    supervisor/supervisor.sh shutdown
    stop_jaeger
    rm -rf traces/*
    mkdir -p logs traces gen gen-cache
    find gen gen-cache -mindepth 1 -maxdepth 1 -exec rm -r {} +
}

cmd_topology() {
    set -e
    cmd_topo_clean

    # Build the necessary binaries.
    bazel build //:scion-topo
    tar --overwrite -xf bazel-bin/scion-topo.tar -C bin

    echo "Create topology, configuration, and execution files."
    is_running_in_docker && set -- "$@" --in-docker
    python/topology/generator.py "$@"
    if is_docker_be; then
        ./tools/quiet ./tools/dc run utils_chowner
    fi
    run_jaeger
    #FIXME(lukedirtwalker): Re-enalbe for v2 trust: load_cust_keys
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
        make -s || exit 1
        if is_docker_be; then
            echo "Build perapp images"
            ./tools/quiet make -C docker prod
            echo "Build scion tester"
            ./tools/quiet make -C docker test
        fi
    fi
    run_setup
    echo "Running the network..."
    # Start dispatcher first, as it is requrired by the border routers.
    if is_docker_be; then
        ./tools/quiet ./scion.sh mstart '*disp*' # for dockerized
    else
        ./tools/quiet ./scion.sh mstart '*dispatcher*' # for supervisor
    fi
    # Start border routers before all other services to provide connectivity.
    ./tools/quiet ./scion.sh mstart '*br*'
    # Run with docker-compose or supervisor
    if is_docker_be; then
        ./tools/quiet ./tools/dc start 'scion*'
    else
        ./tools/quiet ./supervisor/supervisor.sh start all
    fi
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
     # Create dispatcher and sciond dirs or change owner
    local disp_dir="/run/shm/dispatcher"
    [ -d "$disp_dir" ] || mkdir "$disp_dir"
    [ $(stat -c "%U" "$disp_dir") == "$LOGNAME" ] || { sudo -p "Fixing ownership of $disp_dir - [sudo] password for %p: " chown $LOGNAME: "$disp_dir"; }
    local sciond_dir="/run/shm/sciond"
    [ -d "$sciond_dir" ] || mkdir "$sciond_dir"
    [ $(stat -c "%U" "$sciond_dir") == "$LOGNAME" ] || { sudo -p "Fixing ownership of $sciond_dir - [sudo] password for %p: " chown $LOGNAME: "$sciond_dir"; }
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

is_running_in_docker() {
    cut -d: -f 3 /proc/1/cgroup | grep -q '^/docker/'
}

cmd_test(){
    local ret=0
    case "$1" in
        py) shift; py_test "$@"; ret=$((ret+$?));;
        go) shift; bazel_test ; ret=$((ret+$?));;
        *) py_test; ret=$((ret+$?)); bazel_test; ret=$((ret+$?));;
    esac
    return $ret
}

py_test() {
    python3 -m unittest discover
    nosetests3 ${EXTRA_NOSE_ARGS} "$@"
}

bazel_test() {
    bazel test //go/... --print_relative_test_log_paths
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
    py_lint || ret=1
    go_lint || ret=1
    bazel_lint || ret=1
    md_lint || ret=1
    return $ret
}

py_lint() {
    lint_header "python"
    local ret=0
    for i in acceptance python; do
      [ -d "$i" ] || continue
      local cmd="flake8"
      lint_step "$cmd /$i"
      ( cd "$i" && $cmd --config flake8.ini . ) | sort -t: -k1,1 -k2n,2 -k3n,3 || ((ret++))
    done
    flake8 --config python/flake8.ini tools/gomocks || ((ret++))
    return $ret
}

go_lint() {
    lint_header "go"
    local TMPDIR=$(mktemp -d /tmp/scion-lint.XXXXXXX)
    local LOCAL_DIRS="$(find go/* -maxdepth 0 -type d | grep -v vendor)"
    # Find go files to lint, excluding generated code. For linelen and misspell.
    find go acceptance -type f -iname '*.go' \
      -a '!' -ipath 'go/proto/structs.gen.go' \
      -a '!' -ipath 'go/proto/*.capnp.go' \
      -a '!' -ipath '*mock_*' \
      -a '!' -ipath 'go/lib/pathpol/sequence/*' > $TMPDIR/gofiles.list

    lint_step "Building lint tools"
    bazel build //:lint || return 1
    tar -xf bazel-bin/lint.tar -C $TMPDIR || return 1
    local ret=0
    lint_step "impi"
    # Skip CGO (https://github.com/pavius/impi/issues/5) files.
    $TMPDIR/impi --local github.com/scionproto/scion --scheme stdThirdPartyLocal --skip '/c\.go$' --skip 'mock_' --skip 'go/proto/.*\.capnp\.go' --skip 'go/proto/structs.gen.go' ./go/... || ret=1
    $TMPDIR/impi --local github.com/scionproto/scion --scheme stdThirdPartyLocal ./acceptance/... || ret=1
    lint_step "gofmt"
    # TODO(sustrik): At the moment there are no bazel rules for gofmt.
    # See: https://github.com/bazelbuild/rules_go/issues/511
    # Instead we'll just run the commands from Go SDK directly.
    GOSDK=$(bazel info output_base)/external/go_sdk/bin
    out=$($GOSDK/gofmt -d -s $LOCAL_DIRS ./acceptance);
    if [ -n "$out" ]; then echo "$out"; ret=1; fi
    lint_step "linelen (lll)"
    out=$($TMPDIR/lll -w 4 -l 100 --files -e '`comment:"|`ini:"|https?:' < $TMPDIR/gofiles.list);
    if [ -n "$out" ]; then echo "$out"; ret=1; fi
    lint_step "misspell"
    xargs -a $TMPDIR/gofiles.list $TMPDIR/misspell -error || ret=1
    lint_step "ineffassign"
    $TMPDIR/ineffassign -exclude ineffassign.json go acceptance || ret=1
    lint_step "bazel"
    make gazelle GAZELLE_MODE=diff || ret=1
    # Clean up the binaries
    rm -rf $TMPDIR
    return $ret
}

bazel_lint() {
    lint_header "bazel"
    local ret=0
    bazel run //:buildifier_check || ret=1
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
        -e BADGER_CONSISTENCY=true \
        -v "$trace_dir:/badger" \
        -p "$port":16686 \
        jaegertracing/all-in-one:1.16.0
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
	    $PROGRAM traces [folder]
	        Serve jaeger traces from the specified folder (default: traces/)
	    $PROGRAM stop_traces
	        Stop the jaeger container started during the traces command
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift

case "$COMMAND" in
    coverage|help|lint|run|mstart|mstatus|mstop|stop|status|test|topology|version|build|clean|sciond|traces|stop_traces|topo_clean)
        "cmd_$COMMAND" "$@" ;;
    start) cmd_run "$@" ;;
    *)  cmd_help; exit 1 ;;
esac
