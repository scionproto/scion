#!/bin/bash
set -e

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "$SCRIPT_DIR/../.."

# Check that ~/.local/bin is in $PATH
if [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.profile && source ~/.profile
fi

mkdir -p logs traces
./deps.sh all

# Kill the previous instance of supervisor
echo 'Stopping all processes...'
./supervisor/supervisor.sh quickstop all 1> /dev/null
RE_SUPERVISOR="supervisord -c.*supervisor/supervisord.conf"
pkill -f "$RE_SUPERVISOR" || true
sleep 1
pkill -9 -f "$RE_SUPERVISOR" || true

# Start the management daemon
./supervisor/supervisor.sh restart management_daemon
