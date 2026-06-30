#!/bin/bash
# Diagnostics for the clab IPv6 "Address already in use" deploy failures.
# Usage: debug-clab.sh <pre|post>
# Run with `pre` right before `clab deploy` and `post` after a failed deploy.
# Best-effort only: every probe is guarded so the script never fails the build.

phase="${1:-pre}"
net="scion-mgmt"

run() { echo "+ $*"; "$@" 2>&1 || echo "(command failed: $*)"; echo; }

echo "--- clab debug (${phase})"

if [ "${phase}" = "pre" ]; then
    echo "=== versions ==="
    run clab version
    run docker version

    echo "=== docker daemon IPv6 config ==="
    # Whether dockerd has ipv6 + ip6tables enabled is the usual culprit when a
    # topology that deploys locally fails in CI: without ip6tables the daemon
    # cannot manage v6 endpoint addresses and double-assigns them.
    run docker info --format 'IPv6={{.Driver}} cgroup={{.CgroupDriver}}'
    echo "+ cat /etc/docker/daemon.json"
    cat /etc/docker/daemon.json 2>&1 || echo "(no /etc/docker/daemon.json)"
    echo
    run sysctl net.ipv6.conf.all.disable_ipv6 net.ipv6.conf.all.forwarding
    echo "+ ip6tables -t nat -L -n (first lines)"
    sudo ip6tables -t nat -L -n 2>&1 | head -20 || echo "(ip6tables unavailable)"
    echo

    echo "=== host IPv6 state ==="
    run ip -6 addr
    run ip -6 route

    echo "=== pre-existing docker state (leftovers / concurrent runs) ==="
    # If another run (or a failed retry whose cleanup didn't complete) still
    # holds the deterministic static IPs, the next deploy hits 'already in use'.
    run docker ps -a
    run docker network ls
fi

echo "=== ${net} network inspect ==="
# The Containers map shows which container currently owns each IPv4/IPv6
# address. After a failure this reveals exactly what is squatting on the
# address clab tried to assign.
run docker network inspect "${net}"

if [ "${phase}" = "post" ]; then
    echo "=== all containers after failure ==="
    run docker ps -a
    echo "=== clab inspect ==="
    run clab inspect --all
fi
