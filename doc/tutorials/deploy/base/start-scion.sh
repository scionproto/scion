#!/bin/bash
set -euo pipefail

mkdir -p /var/log/scion

# Run SCION services in the background.
scion-dispatcher --config /etc/scion/dispatcher.toml \
    > >(tee /var/log/scion/dispatcher.log) \
    2> >(tee /var/log/scion/dispatcher.log >&2) &

scion-daemon --config /etc/scion/daemon.toml \
    > >(tee /var/log/scion/daemon.log) \
    2> >(tee /var/log/scion/daemon.log >&2) &

scion-control --config /etc/scion/cs.toml \
    > >(tee /var/log/scion/control.log) \
    2> >(tee /var/log/scion/control.log >&2) &

scion-router --config /etc/scion/br.toml \
    > >(tee /var/log/scion/router.log) \
    2> >(tee /var/log/scion/router.log >&2) &

# start the IP-gateway only if its config file exists in this image
if [[ -f /etc/scion/gateway.toml ]]; then
    scion-ip-gateway --config /etc/scion/gateway.toml \
        > >(tee /var/log/scion/gateway.log) \
        2> >(tee /var/log/scion/gateway.log >&2) &
fi

# Wait for any service to exit (fail fast)
wait -n
