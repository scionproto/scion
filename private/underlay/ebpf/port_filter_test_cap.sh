#! /bin/bash

executable=$1
shift

# Try to run with sudo -n (non-interactive). If sudo requires a password,
# this will fail immediately and we skip the test.
if ! /usr/bin/sudo -n capsh --caps="cap_bpf=ep cap_net_admin=ep cap_net_raw=ep" -- -c "$executable" 2>/dev/null; then
    # Check if the failure was due to missing sudo privileges
    if ! /usr/bin/sudo -n true 2>/dev/null; then
        echo "SKIP: Test requires passwordless sudo or pre-existing capabilities (CAP_BPF, CAP_NET_ADMIN, CAP_NET_RAW)"
        exit 0
    fi
    # Some other error occurred, propagate it
    exit 1
fi
