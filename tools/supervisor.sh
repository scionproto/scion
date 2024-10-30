#!/bin/bash

mkdir -p logs

# Wrap the 'supervisorctl' command
OPTIONS="$@"
CONF_FILE="tools/supervisord.conf"
if [ ! -e /tmp/supervisor.sock ]; then
    bin/supervisord -c $CONF_FILE
fi
bin/supervisorctl -c $CONF_FILE $OPTIONS

