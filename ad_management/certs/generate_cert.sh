#!/usr/bin/env bash

# Change directory to the script directory
SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $SCRIPT_DIR/

openssl req -nodes -new -x509 -keyout key.pem -out cert.pem -days 1000 -subj '/CN=127.0.0.1'
