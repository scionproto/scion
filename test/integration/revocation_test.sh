#!/bin/bash

set -o pipefail

log() {
    echo "========> ($(date -u --rfc-3339=seconds)) $@"
}

export PYTHONPATH=.
log "Testing connectivity between all the hosts."
test/integration/end2end_test.py -l ERROR
result=$?
if [ $result -ne 0 ]; then
    log "E2E test failed."
    exit ${result}
fi
# Bring down routers.
SLEEP=5
log "Stopping routers and waiting for ${SLEEP}s."
supervisorctl -s http://localhost:9011 stop as1-11:br1-11-3
supervisorctl -s http://localhost:9011 stop as1-13:br1-13-2
supervisorctl -s http://localhost:9011 stop as2-26:br2-26-2
sleep ${SLEEP}s
# Do another round of e2e test with retries
log "Testing connectivity between all the hosts (with retries)."
test/integration/end2end_test.py -l ERROR --retries 3
result=$?
if [ $result -ne 0 ]; then
    log "E2E test with failed routers failed."
fi
exit ${result}
