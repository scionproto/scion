#!/bin/bash

set -o pipefail

log() {
    echo "========> ($(date -u --rfc-3339=seconds)) $@"
}

shutdown() {
    sudo ip addr delete $client_addr/128 dev lo 2>/dev/null
    sudo ip addr delete $server_addr/128 dev lo 2>/dev/null
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

check_br_exists() {
    ./supervisor/supervisor.sh status $1 | grep -qF ERROR
    if [ $? -eq 0 ]; then
        return 1
    fi
    return 0
}

usage() {
    cat <<EOF
USAGE: $0 [OPTION]

OPTIONS:
    -h  Help
    -6  Run tests with IPv6 addresses

    By default, IPv4 addresses are used
EOF
}

export -f run log

export PYTHONPATH=python/:.

if [ $# -gt 1 ]; then
    echo "Invalid options"
    usage $0
    exit 1
fi
client_addr="127.0.0.2"
server_addr="127.0.0.3"
case $1 in
    -h)
        usage $0
        exit
        ;;
    -6)
        client_addr="::127:0:0:2"
        server_addr="::127:0:0:3"
        sudo ip addr add $client_addr/128 dev lo 2>/dev/null
        sudo ip addr add $server_addr/128 dev lo 2>/dev/null
        ;;
esac

log "Starting scion (without building)"
./scion.sh run nobuild | grep -v "started"
log "Scion status:"
./scion.sh status || exit 1

sleep 5

cat << EOF | parallel --no-notice -n2 -j2 run
End2End
python/integration/end2end_test.py --client $client_addr --server $server_addr -l ERROR
C2S_extn
python/integration/cli_srv_ext_test.py --client $client_addr --server $server_addr -l ERROR
SCMP error
python/integration/scmp_error_test.py --client $client_addr --server $server_addr -l ERROR --runs 60
Cert/TRC request
python/integration/cert_req_test.py --client $client_addr --server $server_addr -l ERROR
EOF
result=$?

REV_BRS="as1-11:br1-11-3 as2-26:br2-26-2 as1-14:br1-14-3 as1-16:br1-16-2"
for br in $REV_BRS; do
    if ! check_br_exists "$br"; then
        log "${br} does not exist. Skipping revocation test."
        shutdown
        exit 0
    fi
done

# Bring down routers.
SLEEP=4
log "Stopping routers and waiting for ${SLEEP}s."
./supervisor/supervisor.sh stop $REV_BRS
if [ $? -ne 0 ]; then
    log "Failed stopping routers."
    shutdown
    exit 1
fi
sleep ${SLEEP}s
# Do another round of e2e test with retries
log "Testing connectivity between all the hosts (with retries)."
python/integration/end2end_test.py --client $client_addr --server $server_addr -l ERROR --retries 3
if [ $? -ne 0 ]; then
    log "E2E test with failed routers failed. ($?)"
fi

result=$((result+$?))
shutdown

if [ $result -eq 0 ]; then
    log "All tests successful"
else
    log "$result tests failed"
fi
exit $result
