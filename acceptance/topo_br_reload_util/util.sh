#!/bin/bash

SRC_IA=${SRC_IA:-1-ff00:0:111}
SRC_IA_FILE=$(echo $SRC_IA | sed -e "s/:/_/g")
SRC_AS_FILE=$(echo $SRC_IA_FILE | cut -d '-' -f 2)
DST_IA=${DST_IA:-1-ff00:0:110}
DST_IA_FILE=$(echo $DST_IA | sed -e "s/:/_/g")
DST_AS_FILE=$(echo $DST_IA_FILE | cut -d '-' -f 2)


check_logs() {
    fgrep -q "$1" "logs/br$2-1.log" || { echo "Not found: $1"; return 1; }
}

base_setup() {
    set -e
    ./scion.sh topology zkclean -c $TEST_TOPOLOGY -d
    for sd in gen/ISD1/*/br*/brconfig.toml; do
        sed -i '/\[logging\.file\]/a FlushInterval = 1' "$sd"
    done
    ./scion.sh run nobuild
    ./tools/dc start tester_$SRC_IA_FILE
}

base_teardown() {
    ./tools/dc down
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
