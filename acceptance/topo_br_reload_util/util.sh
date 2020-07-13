#!/bin/bash

SRC_IA=${SRC_IA:-1-ff00:0:111}
SRC_IA_FILE=$(echo $SRC_IA | sed -e "s/:/_/g")
SRC_AS_FILE=$(echo $SRC_IA_FILE | cut -d '-' -f 2)
SRC_TOPO="gen/ISD1/AS$SRC_AS_FILE/br$SRC_IA_FILE-1/topology.json"

DST_IA=${DST_IA:-1-ff00:0:110}
DST_IA_FILE=$(echo $DST_IA | sed -e "s/:/_/g")
DST_AS_FILE=$(echo $DST_IA_FILE | cut -d '-' -f 2)
DST_TOPO="gen/ISD1/AS$DST_AS_FILE/br$DST_IA_FILE-1/topology.json"

. acceptance/common.sh

check_logs() {
    docker-compose -f gen/scion-dc.yml -p scion logs "scion_br$2-1" | fgrep -q "$1" || fail "Not found: $1"
}

check_connectivity() {
    bin/end2end_integration -src $SRC_IA -dst $DST_IA -attempts 5 -d || fail "FAIL: Traffic does not pass. step=( $1 )"
}

unqoute() {
    echo "$(jq -r '.' <(echo "$1"))"
}

base_setup() {
    set -e
    base_gen_topo
    base_run_topo
}

base_gen_topo() {
    ./scion.sh topology -c $TEST_TOPOLOGY -d
}

base_run_topo() {
    set -e
    ./scion.sh run nobuild
    ./tools/dc start tester*
    sleep 5
    docker_status
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
