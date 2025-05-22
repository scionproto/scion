#!/bin/bash
set -euo pipefail

# Run SCION services in the background.
scion-dispatcher --config /etc/scion/dispatcher.toml &
scion-daemon --config /etc/scion/daemon.toml &
scion-control --config /etc/scion/cs.toml &
scion-router --config /etc/scion/br.toml &

# start the IP-gateway only if its config file exists in this image
if [[ -f /etc/scion/gateway.toml ]]; then
    scion-ip-gateway --config /etc/scion/gateway.toml &
fi

# Wait for any service to exit (fail fast)
wait -n
