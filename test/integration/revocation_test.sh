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
log "Stopping routers."
supervisorctl -s http://localhost:9011 stop as1-11:br1-11-3
sleep 5
# Do another round of e2e test with retries
log "Testing connectivity between all the hosts (with retries)."
test/integration/end2end_test.py -l ERROR --retries 3
exit $?
