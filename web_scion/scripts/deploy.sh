#!/bin/bash

mkdir -p logs traces
./scion.sh deps
./scion.sh init

# Kill the previous instance of supervisor
RE_SUPERVISOR="supervisord -c.*supervisor/supervisord.conf"
pkill -f "$RE_SUPERVISOR" && sleep 1 && pkill -9 -f "$RE_SUPERVISOR"

./supervisor/supervisor.sh restart monitoring_daemon
