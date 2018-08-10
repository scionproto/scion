#!/bin/bash
# Copyright 2018 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

. integration/common.sh

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

log "Starting scion (without building)"
./scion.sh run nobuild | grep -v "started"
log "Scion status:"
./scion.sh status || exit 1


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

if [ -z $CONTAINER ]; then
    integration/revocation_test.sh\
    ${REV_BRS:-*br1-ff00_0_110-3 *br2-ff00_0_222-2 *br1-ff00_0_111-3 *br1-ff00_0_131-2}
else
    integration/revocation_test.sh -docker $CONTAINER\
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
