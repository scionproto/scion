#!/bin/bash
set -e

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "$SCRIPT_DIR/../.."

mkdir -p logs traces
./scion.sh deps
./scion.sh init

# Kill the previous instance of supervisor
RE_SUPERVISOR="supervisord -c.*supervisor/supervisord.conf"
pkill -f "$RE_SUPERVISOR" || true
sleep 1
pkill -9 -f "$RE_SUPERVISOR" || true

# Start the monitoring daemon
./supervisor/supervisor.sh start monitoring_daemon
