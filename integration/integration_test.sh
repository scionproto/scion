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
    ./scion.sh stop | grep -v "stopped"
    log "Scion stopped"
}

run() {
    log "${1:?}: starting"
    time ${2:?}
    local result=$?
    if [ $result -eq 0 ]; then
        log "$1: success"
    else
        log "$1: failure"
    fi
    return $result
}
export -f run log

export PYTHONPATH=python/:.

log "Starting scion (without building)"
./scion.sh run nobuild | grep -v "started"
log "Scion status:"
./scion.sh status || exit 1

sleep 5
# Sleep for longer if running in circleci, to reduce flakiness due to slow startup:
[ -n "$CIRCLECI" ] && sleep 10

cat << EOF | parallel --no-notice -n2 -j2 run
End2End
python/integration/end2end_test.py -l ERROR
C2S_extn
python/integration/cli_srv_ext_test.py -l ERROR
SCMP error
python/integration/scmp_error_test.py -l ERROR --runs 60
Cert/TRC request
python/integration/cert_req_test.py -l ERROR
EOF
result=$?

run Revocation "integration/revocation_test.sh\
 ${REV_BRS:-as1-ff00_0_110:br1-ff00_0_110-3 as2-ff00_0_222:br2-ff00_0_222-2 as1-ff00_0_111:br1-ff00_0_111-3 as1-ff00_0_131:br1-ff00_0_131-2}"
result=$((result+$?))

shutdown

if [ $result -eq 0 ]; then
    log "All tests successful"
else
    log "$result tests failed"
fi
exit $result
