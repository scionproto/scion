#!/bin/bash

POX_PID=/tmp/pox.pid
POX_LOG=/tmp/pox.log
POX_PORT=6633

if [ -e "$POX_PID" ]; then
    echo "ERROR: Pox already running, or $POX_PID is stale"
    exit 1
fi

pox forwarding.l2_learning misc.pidfile --file=$POX_PID log --no_default --file=$POX_LOG,w --format="%(asctime)s: %(message)s" &
#wait for pox to start to avoid "can't connect to controller errors"
sleep 1
if nc -z localhost $POX_PORT; then
    echo "POX running on localhost:$POX_PORT"
else
    echo "ERROR: Pox not running:"
    echo "======================="
    cat "$POX_LOG"
    exit 1
fi
sudo SUPERVISORD=$(which supervisord) python topology/mininet/topology.py

echo "Stopping POX"
kill $(< $POX_PID)
