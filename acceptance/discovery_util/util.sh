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
    local port=$( echo $addr | awk '{printf $2}' )
    sed -e "s/REPLACE_PORT/$port/g" "$UTIL_PATH/Dockerfile.tmpl" > "$HTTP_DIR/Dockerfile"
    docker build -f "$HTTP_DIR/Dockerfile" -t "scion_discovery_test:latest" $UTIL_PATH
    # Modify docker compose file to contain discovery.
    local network=$(awk '/  scion_disp_1-ff00_0_111:/,/ volumes/ {if (f=="networks:") {gsub(":", "",$1); print $1}} {f=$1}' gen/scion-dc.yml)
    local ip=$( echo $addr | awk '{printf $1}' )
    local dc_cfg="$( quoteSubst "$( sed -e "s/REPLACE_NETWORK/$network/" -e "s/REPLACE_IP/$ip/" "$UTIL_PATH/dc.tmpl")" )"
    sed -i -e "/services:/a \  $dc_cfg" "gen/scion-dc.yml"
}

set_log_lvl() {
    sed -i -e 's/Level = .*$/Level = "trace"/g' -e '/\[logging\.file\]/a FlushInterval = 1' "$1"
}

set_interval() {
    sed -i -e "/\[discovery.$2]/a Interval = \"1s\"" "$1"
}

quoteSubst() {
    # Copied from https://stackoverflow.com/a/29613573
    IFS= read -d '' -r < <(sed -e ':a' -e '$!{N;ba' -e '}' -e 's/[&/\]/\\&/g; s/\n/\\&/g' <<<"$1")
    printf %s "${REPLY%$'\n'}"
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
