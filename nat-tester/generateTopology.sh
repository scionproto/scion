#!/bin/sh

if [ "$(basename "$PWD")" != "scion" ]; then
  echo "Error: this script must be run from the scion directory." >&2
  exit 1
fi

sh -c "./scion.sh topology -d -c topology/tiny.topo" &&
python3 nat-tester/modify_topology.py
