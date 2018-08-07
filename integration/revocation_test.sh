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

set -o pipefail

log() {
    echo "========> ($(date -u --rfc-3339=seconds)) $@"
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

# See if docker is wanted and get the testing container
if [ "$1" = "docker" ]; then
    shift
    container="${1:-scion_ci}"
    shift
fi

for br in "$@"; do
    if ! ./scion.sh mstatus "$br"; then
        log "${br} does not exist. Skipping revocation test."
        exit 0
    fi
done

export PYTHONPATH=python/:.
# Bring down routers.
SLEEP=4
log "Revocation: starting"
log "Stopping routers and waiting for ${SLEEP}s."
./scion.sh mstop "$@"
if [ $? -ne 0 ]; then
    log "Failed stopping routers."
    exit 1
fi
sleep ${SLEEP}s
# Do another round of e2e test with retries
log "Testing connectivity between all the hosts (with retries)."
run Revocation "python/integration/end2end_test.py -l ERROR --retries 3"
exit $?
