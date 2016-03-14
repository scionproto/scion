#!/bin/bash

set -o pipefail

log() {
    echo "========> ($(date -u --rfc-3339=seconds)) $@"
}

wait_startup() {
    count=0
    while true; do
        log "Waiting for host ZK to be up (count:$count)"
        { echo "ruok" | nc localhost 2181 | grep -q 'imok'; } && break
        count=$((count+1))
        if [ $count -gt 20 ]; then
            log "Host ZK failed to come up within 1 minute"
            exit 1
        fi
        sleep 3
    done
    log "Host ZK up"
}

shutdown() {
    log "Scion status:"
    ./scion.sh status
    log "Stopping scion"
    ./scion.sh stop | grep -v "STOPPED"
    log "Scion stopped"
    exit $result
}

export PYTHONPATH=.

log "Building dispatcher"
./scion.sh build
log "Starting scion"
./scion.sh run | grep -v "RUNNING"
log "Scion status:"
./scion.sh status || exit 1

log "End2end starting:"
test/integration/end2end_test.py
result=$?
if [ $result -eq 0 ]; then
    log "End2end: success"
else
    log "End2end: failure"
    shutdown
fi

log "C2S_extn starting:"
test/integration/cli_srv_ext_test.py 1-19 2-26
result=$?
if [ $result -eq 0 ]; then
    log "C2S_extn: success"
else
    log "C2S_extn: failure"
fi

shutdown
