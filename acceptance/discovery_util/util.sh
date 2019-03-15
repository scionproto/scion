#!/bin/bash

. acceptance/common.sh

IA=${IA:-1-ff00:0:111}
IA_FILE="$(ia_file $IA)"
AS_FILE="$(as_file $IA)"
TOPO="gen/ISD1/AS$AS_FILE/br$IA_FILE-1/topology.json"

UTIL_PATH="acceptance/discovery_util"
TEST_TOPOLOGY="topology/Tiny.topo"

HTTP_DIR="gen/discovery_acceptance"
STATIC_DIR="$HTTP_DIR/discovery/v1/static"
STATIC_FULL="$STATIC_DIR/full.json"
STATIC_DEFAULT="$STATIC_DIR/default.json"
DYNAMIC_DIR="$HTTP_DIR/discovery/v1/dynamic"
DYNAMIC_FULL="$DYNAMIC_DIR/full.json"
DYNAMIC_DEFAULT="$DYNAMIC_DIR/default.json"


base_setup() {
    set -e
    # Create topology setup all necessary config files.
    ./scion.sh topology nobuild -c "$TEST_TOPOLOGY" -d -ds
    # Create the topology directories for serving.
    mkdir -p "$STATIC_DIR"
    mkdir -p "$DYNAMIC_DIR"

    # Get ip and port for the discovery service.
    local addr=$( jq -r '.DiscoveryService[].Addrs[].Public | "\(.Addr) \(.L4Port)"' "$TOPO" )

    # Build mock discovery service container.
    docker build -f "$UTIL_PATH/Dockerfile" -t "scion_discovery_test:latest" $UTIL_PATH --build-arg port=$( echo $addr | awk '{printf $2}' )

    export DISC_IP=$( echo $addr | awk '{printf $1}' )
    # Find absolute path of the scion dir in the docker compose file.
    # This allows the test to work locally and on the CI.
    export DISC_DIR="$( grep -oh '\/.*\/gen' gen/scion-dc.yml | grep -v ':' -m 1 )/discovery_acceptance"

    # Get the network AS 1-ff00_0_111 is on. And replace it in the template.
    local network=$(awk '/  scion_disp_1-ff00_0_111:/,/ volumes/ {if (f=="networks:") {gsub(":", "",$1); print $1}} {f=$1}' gen/scion-dc.yml)
    # Modify docker compose file to contain mock discovery service.
    sed -e "s/REPLACE_NETWORK/$network/" "$UTIL_PATH/dc.tmpl" | sed -i -e "/services:/r /dev/stdin" "gen/scion-dc.yml"
}

base_start_scion() {
    ./scion.sh run nobuild
    ./tools/dc scion up -d 'mock_ds1-ff00_0_111-1'
}

set_log_lvl() {
    sed -i -e 's/Level = .*$/Level = "trace"/g' -e '/\[logging\.file\]/a FlushInterval = 1' "$1"
}

set_interval() {
    sed -i -e "/\[discovery.$2]/a Interval = \"1s\"" "$1"
}

set_connect() {
    printf "\n[discovery.$2.Connect]\nInitialPeriod = \"$3\"" >> "$1"
}

set_fail_action() {
    sed -i -e "/\[discovery.$2.Connect]/a FailAction = \"$3\"" "$1"
}

check_file() {
    curl -f -s -S "$( jq -r '.DiscoveryService[].Addrs[].Public | "\(.Addr):\(.L4Port)"' "$TOPO" )/discovery/v1/$1/full.json" > /dev/null
    curl -f -s -S "$( jq -r '.DiscoveryService[].Addrs[].Public | "\(.Addr):\(.L4Port)"' "$TOPO" )/discovery/v1/$1/default.json" > /dev/null
}


check_infra_fail_action() {
    stop_mock_ds
    # Check that services continue if fail action is not set.
    for cfg in gen/ISD1/AS$AS_FILE/*/{cs,ps,sd}config.toml; do
        set_connect "$cfg" "$1" "5s"
    done
    ./tools/dc scion restart "scion_ps$IA_FILE-1" "scion_cs$IA_FILE-1" "scion_sd$IA_FILE"
    sleep 10
    check_running "ps$IA_FILE-1" || fail "Error: ps$IA_FILE-1 not running"
    check_running "cs$IA_FILE-1" || fail "Error: cs$IA_FILE-1 not running"
    check_running "sd$IA_FILE" || fail "Error: sd$IA_FILE not running"

    # Check that services exit if fail action is fatal
    for cfg in gen/ISD1/AS$AS_FILE/*/{cs,ps,sd}config.toml; do
        set_fail_action "$cfg" "$1" "Fatal"
    done
    ./tools/dc scion restart "scion_ps$IA_FILE-1" "scion_cs$IA_FILE-1" "scion_sd$IA_FILE"
    sleep 10
    check_not_running "ps$IA_FILE-1" || fail "Error: ps$IA_FILE-1 still running"
    check_not_running "cs$IA_FILE-1" || fail "Error: cs$IA_FILE-1 still running"
    check_not_running "sd$IA_FILE" || fail "Error: sd$IA_FILE still running"
}

check_br_fail_action() {
    stop_mock_ds
    # Check that border router continues if fail action is not set.
    set_connect "gen/ISD1/AS$AS_FILE/br$IA_FILE-1/brconfig.toml" "$1" "5s"
    ./tools/dc scion restart "scion_br$IA_FILE-1"
    sleep 10
    check_running "br$IA_FILE-1" || fail "Error: br$IA_FILE-1 not running"

    # Check that border router exits if fail action is fatal
    set_fail_action "gen/ISD1/AS$AS_FILE/br$IA_FILE-1/brconfig.toml" "$1" "Fatal"
    ./tools/dc scion restart "scion_br$IA_FILE-1"
    sleep 10
    check_not_running "br$IA_FILE-1" || fail "Error: br$IA_FILE-1 still running"
}

stop_mock_ds() {
    ./tools/dc scion stop 'mock_ds1-ff00_0_111-1'
}

check_running() {
    if is_running_in_docker; then
            local docker="docker_"
    fi
    docker top "scion_${docker}$1"
}

check_not_running() {
    check_running $1 || local running="nope"
    [ "$running" == "nope" ] || return 1
}

print_help() {
    echo
	cat <<-_EOF
	    $PROGRAM name
	        return the name of this test
	    $PROGRAM setup
	        execute only the setup phase.
	    $PROGRAM run
	        execute only the run phase.
	    $PROGRAM teardown
	        execute only the teardown phase.
	_EOF
}

PROGRAM=`basename "$0"`
COMMAND="$1"

do_command() {
    PROGRAM="$1"
    COMMAND="$2"
    TEST_NAME="$3"
    shift 3
    case "$COMMAND" in
        name)
            echo $TEST_NAME ;;
        setup|run|teardown)
            "test_$COMMAND" "$@" ;;
        *) print_help; exit 1 ;;
    esac
}
