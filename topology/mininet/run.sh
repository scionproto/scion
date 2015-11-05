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

#wait for pox to start to avoid "can't connect to controller errors"
sleep 1
if nc -z localhost $POX_PORT; then
    log "POX running on localhost:$POX_PORT"
else
    log "ERROR: Pox not running:"
    tail -n 20 "$POX_LOG"
    exit 1
fi

log "Starting mininet"
sudo SUPERVISORD=$(which supervisord) python topology/mininet/topology.py

for i in "$TMP_DIR"/*.pid; do
    log "Killing $(basename $i | cut -d. -f -1)"
    kill $(< $i)
done
