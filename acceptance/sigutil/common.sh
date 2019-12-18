#!/bin/bash

TEST_TOPOLOGY=${TEST_TOPOLOGY:-topology/Tiny.topo}
SRC_IA=${SRC_IA:-1-ff00:0:111}
DST_IA=${DST_IA:-1-ff00:0:112}

. acceptance/sigutil/command_wrapper.sh

test_setup() {
    set -e
    ./scion.sh topology nobuild -c $TEST_TOPOLOGY -d -t --sig -n 242.254.0.0/16
    for sig in gen/ISD1/*/sig*/sig.toml; do
        sed -i '/\[logging\.file\]/a FlushInterval = 1' "$sig"
    done
    ./scion.sh run nobuild
    ./tools/dc start 'tester*'
    sleep 7
    docker_status
}

reload_sig() {
    log "Reloading SIG config for $1"
    id="$(./tools/dc scion exec -T scion_sig_$1 pgrep -x sig)"
    ./tools/dc scion exec -T scion_sig_"$1" kill -SIGHUP "$id"
    # Wait till the new config takes effect.
    sleep 3
    # Make sure that the reload actually happened.
    COUNT=$(grep --text ".*Config reloaded.*" "logs/sig$1.log" | wc -l)
    if [ "$COUNT" != "$2" ]; then
            echo "Expected $2 config reloads, found $COUNT."
        exit 1
    fi
}
