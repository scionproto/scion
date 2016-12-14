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

export PYTHONPATH=.
log "Testing connectivity between all the hosts."
test/integration/end2end_test.py -l ERROR
result=$?
if [ ${result} -ne 0 ]; then
    log "E2E test failed."
    exit ${result}
fi
# Bring down routers.
SLEEP=10
log "Stopping routers and waiting for ${SLEEP}s."
supervisorctl -s http://localhost:9011 stop as1-11:br1-11-3 > /dev/null
supervisorctl -s http://localhost:9011 stop as2-26:br2-26-2 > /dev/null
sleep ${SLEEP}s
# Do another round of e2e test with retries
log "Testing connectivity between all the hosts (with retries)."
test/integration/end2end_test.py -l ERROR --retries 3
result=$?
if [ $result -ne 0 ]; then
    log "E2E test with failed routers failed."
fi
exit ${result}
