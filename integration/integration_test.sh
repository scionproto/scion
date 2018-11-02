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

# Get BRS
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

sleep 10
result=0

# Run go infra test
integration/go_infra
result=$((result+$?))

# Run python integration tests
integration/py_integration
result=$((result+$?))

# Run go integration tests
integration/go_integration
result=$((result+$?))

integration/revocation_test.sh -b "$REV_BRS"
result=$((result+$?))

shutdown

if [ $result -eq 0 ]; then
    log "All integration tests successful"
else
    log "$result integration tests failed"
fi
exit $result
