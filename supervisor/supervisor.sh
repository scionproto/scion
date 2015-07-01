#!/usr/bin/env bash

# Get the full path to the script directory
SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
INFR_PATH="${SCRIPT_DIR}/../infrastructure"
cd $INFR_PATH
mkdir -p ../logs

# Add ~/.local/bin to $PATH
export PATH="$PATH:$HOME/.local/bin"

# Wrap the 'supervisorctl' command
OPTIONS="$@"
CONF_FILE="${SCRIPT_DIR}/supervisord.conf"
supervisord -c $CONF_FILE &> /dev/null
supervisorctl -c $CONF_FILE $OPTIONS

