#!/bin/bash

build_image() {
  docker build -t web_scion .
}

run_image() {
  docker run -p 127.0.0.1:8000:8000 -it web_scion
}

if ! ( [ $(id -u) -eq 0 ] || groups | grep -q "\<docker\>"; ); then
    echo "Error: you must either be root, or in the 'docker' group"
    exit 1
fi

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd $SCRIPT_DIR

build_image && run_image
