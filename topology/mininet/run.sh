#!/bin/bash

TMP_DIR=/tmp/mininet
mkdir -p "$TMP_DIR"

POX_PID="$TMP_DIR/pox.pid"
POX_LOG="logs/pox.log"
POX_OUT="logs/pox.out"
POX_PORT=6633

log() {
    echo "=====> $@"
}
bash gen/zk_datalog_dirs.sh || exit 1

if [ -e "$POX_PID" ]; then
    log "ERROR: Pox already running, or $POX_PID is stale"
    exit 1
fi

PYTHONPATH=topology/mininet pox \
    pox_signal \
    forwarding.l2_learning \
    misc.pidfile --file=$POX_PID \
    log --no_default --file="$POX_LOG" --format="%(asctime)s: %(message)s" \
    &> "$POX_OUT" &

count=0
while ! nc -4 -z localhost "$POX_PORT"; do
    log "Waiting for POX to load on localhost:$POX_PORT"
    sleep 1
    ((count++))
    if [ $count -ge 5 ]; then
        log "ERROR: POX not running after 5 seconds:"
        tail -n 20 "$POX_LOG"
        exit 1
    fi
done

log "POX running on localhost:$POX_PORT"
log "Starting mininet"

sudo SUPERVISORD=$(which supervisord) python topology/mininet/topology.py

for i in "$TMP_DIR"/*.pid; do
    log "Killing $(basename $i | cut -d. -f -1)"
    kill $(< $i)
done
