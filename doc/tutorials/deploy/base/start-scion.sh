#!/bin/bash
set -euo pipefail

mkdir -p /var/log/scion

# Run SCION services in the background.
scion-dispatcher --config /etc/scion/dispatcher.toml 2>&1 | tee /var/log/scion/dispatcher.log &
scion-daemon --config /etc/scion/daemon.toml 2>&1 | tee /var/log/scion/daemon.log &
scion-control --config /etc/scion/cs.toml 2>&1 | tee /var/log/scion/control.log &
scion-router --config /etc/scion/br.toml 2>&1 | tee /var/log/scion/router.log &

# start the IP-gateway only if its config file exists in this image
if [[ -f /etc/scion/gateway.toml ]]; then
    scion-ip-gateway --config /etc/scion/gateway.toml &
fi

# Wait for any service to exit (fail fast)
wait -n
