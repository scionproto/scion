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

check_br_exists() {
    ./supervisor/supervisor.sh status ${br} | grep -qF ERROR
    if [ $? -eq 0 ]; then
        return 1
    fi
    return 0
}

for br in "$@"; do
    if ! check_br_exists "$br"; then
        log "${br} does not exist. Skipping revocation test."
        exit 0
    fi
done

export PYTHONPATH=python/:.
# Bring down routers.
SLEEP=4
log "Stopping routers and waiting for ${SLEEP}s."
./supervisor/supervisor.sh stop "$@"
if [ $? -ne 0 ]; then
    log "Failed stopping routers."
    exit 1
fi
sleep ${SLEEP}s
# Do another round of e2e test with retries
log "Testing connectivity between all the hosts (with retries)."
python/integration/end2end_test.py -l ERROR --retries 3
result=$?
if [ $result -ne 0 ]; then
    log "E2E test with failed routers failed. (${result})"
fi
exit ${result}
