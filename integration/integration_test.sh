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

set -o pipefail

. integration/common.sh

# Get docker flag and container name
opts "$@"
shift $((OPTIND-1))

shutdown() {
    log "Scion status:"
    ./scion.sh status
    log "Stopping scion"
    ./scion.sh stop | grep -v "stopped"
    log "Scion stopped"
}

log "Starting scion (without building)"
./scion.sh run nobuild | grep -v "started" || exit 1
log "Scion status:"
./scion.sh status || exit 1

sleep 5
# Sleep for longer if running in circleci, to reduce flakiness due to slow startup:
if [ -n "$CIRCLECI" ]; then
    sleep 10
    [ -n "$CONTAINER"] && sleep 40
fi

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

[ -n "$CONTAINER" ] && rev_args="-d $CONTAINER"
integration/revocation_test.sh -b "$REV_BRS" $rev_args
result=$((result+$?))

shutdown

if [ $result -eq 0 ]; then
    log "All integration tests successful"
else
    log "$result integration tests failed"
fi
exit $result
