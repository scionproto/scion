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

run() {
    log "${1:?}: starting"
    time ${2:?}
    result=$?
    if [ $result -eq 0 ]; then
        log "$1: success"
    else
        log "$1: failure"
    fi
    return $result
}
export -f run log

export PYTHONPATH=.

log "Compiling"
make -s c install || exit 1
log "Starting scion"
./scion.sh run nobuild | grep -v "RUNNING"
log "Scion status:"
./scion.sh status || exit 1

sleep 5

cat << EOF | parallel -n2 -j0 run
End2End
test/integration/end2end_test.py -l ERROR
C2S_extn
test/integration/cli_srv_ext_test.py -l ERROR
SCMP error
test/integration/scmp_error_test.py -l ERROR --runs 60
Cert/TRC request
test/integration/cert_req_test.py -l ERROR
Sibra Ext
test/integration/sibra_ext_test.py -l ERROR --wait 30 --runs 10
SSP
test/integration/ssp_test.py -l ERROR
EOF
result=$?

shutdown

return $result
