#!/bin/bash
set -e

if [ -n "$REMOTE_NETS" ] && [ -n "$SIG_IP" ]; then
    for net in $(echo $REMOTE_NETS | tr , ' '); do
        ip route add "$net" via $SIG_IP dev eth0
    done
fi
echo "Tester started"
tail -f /dev/null
