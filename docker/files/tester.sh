#!/bin/bash
set -e

term() {
  exit 0
}

trap term TERM

if [ -n "$REMOTE_NETS" ] && [ -n "$SIG_IP" ]; then
    for net in $(echo $REMOTE_NETS | tr , ' '); do
        ip route add "$net" via $SIG_IP dev eth0
    done
fi
echo "Tester started"

# Wake up from sleep once in a while so that SIGTERM is handled.
while :
do
    sleep 0.1
done
