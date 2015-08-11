#!/bin/bash

log() {
    echo "========> ($(date -u --rfc-3339=seconds)) $@"
}

log "Starting scion"
./scion.sh run || exit 1
log "Scion started"
log "Scion status: checking"
./scion.sh status || exit 1
log "Scion status: healthy"
log "Test starting: end2end"
( cd test/integration; PYTHONPATH=../../ python3 end2end_test.py; )
log "Test success: end2end"
log "Scion status: checking"
./scion.sh status
log "Scion status: healthy"
log "Stopping scion"
./scion.sh stop
log "Scion stopped"
