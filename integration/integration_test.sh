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

run_docker() {
    cmd="$@"
    docker container exec $container bash -c "PYTHONPATH=python/:. $cmd"
    return $?
}

run() {
    test="${1:?}"
    shift
    log "$test: starting"
    if [ -z "$container" ]; then
        time $@
    else
        time run_docker "$@"
    fi
    local result=$?
    if [ $result -eq 0 ]; then
        log "$test: success"
    else
        log "$test: failure"
    fi
    return $result
}
export -f run log

export PYTHONPATH=python/:.

log "Starting scion (without building)"
./scion.sh run nobuild | grep -v "started"
log "Scion status:"
./scion.sh status || exit 1

# See if docker is wanted and get the testing container
if [ "$1" = "docker" ]; then
    shift
    container="${1:-scion_ci}"
    docker inspect "$container" &>/dev/null || \
    { echo "Container $container not found, aborting!"; shutdown; exit 1; }
    shift
fi

sleep 5

# Run integration tests
run End2End python/integration/end2end_test.py -l ERROR
result=$?
run C2S_extn python/integration/cli_srv_ext_test.py -l ERROR
result=$((result+$?))
run SCMP_error python/integration/scmp_error_test.py -l ERROR --runs 60
result=$((result+$?))
run Cert/TRC_request python/integration/cert_req_test.py -l ERROR
result=$((result+$?))

# Run go integration test
GO_INFRA_TEST="go test -tags infrarunning"
for i in ./go/lib/{snet,pathmgr,infra/disp}; do
    run "Go Infra: $i" ${GO_INFRA_TEST} $i
    result=$((result+$?))
done

# Run (new) go integration tests
for i in ./bin/*_integration; do
    run "Go Integration: $i" "$i"
    result=$((result+$?))
done

if [ -z $container ]; then
    integration/revocation_test.sh\
    ${REV_BRS:-*br1-ff00_0_110-3 *br2-ff00_0_222-2 *br1-ff00_0_111-3 *br1-ff00_0_131-2}
else
    integration/revocation_test.sh docker $container\
    ${REV_BRS:-*br1-ff00_0_110-3 *br2-ff00_0_222-2 *br1-ff00_0_111-3 *br1-ff00_0_131-2}
fi
result=$((result+$?))

shutdown

if [ $result -eq 0 ]; then
    log "All tests successful"
else
    log "$result tests failed"
fi
exit $result
