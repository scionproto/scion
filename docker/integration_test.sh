#!/bin/bash

log() {
    echo "========> ($(date -u --rfc-3339=seconds)) $@"
}

set -o pipefail

log "Starting scion"
./scion.sh run | grep -v "RUNNING"
log "Scion status:"
./scion.sh status || exit 1
log "End2end starting:"
( cd test/integration; PYTHONPATH=../../ python3 end2end_test.py; )
result=$?
if [ $result -eq 0 ]; then
    log "End2end: success"
else
    log "End2end: failure"
fi
log "Scion status:"
./scion.sh status
log "Stopping scion"
./scion.sh stop | grep -v "STOPPED"
log "Scion stopped"
exit $result
