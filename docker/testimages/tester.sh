#!/bin/bash
set -ex

if [ -n "$REMOTE_NETS" ] && [ -n "$SIG_IP" ]; then
    for net in $(echo $REMOTE_NETS | tr , ' '); do
        ip route add "$net" via $SIG_IP dev eth0
    done
fi
tail -f /dev/null
