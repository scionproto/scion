#!/bin/bash

. acceptance/common.sh

IA=${IA:-1-ff00:0:111}
IA_FILE="$(ia_file $IA)"
AS_FILE="$(as_file $IA)"
TOPO="gen/ISD1/AS$AS_FILE/br$IA_FILE-1/topology.json"

UTIL_PATH="acceptance/discovery_util"
TEST_TOPOLOGY="topology/Tiny.topo"

HTTP_DIR="gen/discovery_acceptance"
STATIC_DIR="$HTTP_DIR/discovery/v1/dynamic"
STATIC_FULL="$STATIC_DIR/full.json"
DYNAMIC_DIR="$HTTP_DIR/discovery/v1/dynamic"
DYNAMIC_FULL="$DYNAMIC_DIR/full.json"


base_setup() {
    set -e
    # Create topology setup all necessary config files.
    ./scion.sh topology -c "$TEST_TOPOLOGY" -d -ds
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

set_log_lvl() {
    sed -i -e 's/Level = .*$/Level = "trace"/g' -e '/\[logging\.file\]/a FlushInterval = 1' "$1"
}

set_interval() {
    sed -i -e "/\[discovery.$2]/a Interval = \"1s\"" "$1"
}

check_file() {
    curl -f -s -S "$( jq -r '.DiscoveryService[].Addrs[].Public | "\(.Addr):\(.L4Port)"' "$TOPO" )/discovery/v1/$1/full.json" > /dev/null
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
