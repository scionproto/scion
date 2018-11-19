#!/bin/bash
# Copyright 2016 ETH Zurich
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

set -f

. integration/common.sh

# Get BRS
opts "$@"
shift $((OPTIND-1))

for br in $REV_BRS; do
    if ! ./scion.sh mstatus "$br"; then
        log "${br} does not exist. Skipping revocation test."
        exit 0
    fi
done

# Bring down routers.
SLEEP=4
log "Revocation test"
log "Stopping routers and waiting for ${SLEEP}s."
./scion.sh mstop $REV_BRS
if [ $? -ne 0 ]; then
    log "Failed stopping routers."
    exit 1
fi
sleep ${SLEEP}s
# Do another round of e2e test with retries
log "Testing connectivity between all the hosts (with retries)."
run Revocation bin/end2end_integration -log.console error -attempts 7 $DOCKER_ARGS
exit $?
