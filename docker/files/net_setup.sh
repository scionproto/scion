#!/bin/bash

# This is meant for testing the VPP router/gateway
# For all interfaces:
# 1. removes the IP address
# 2. adds iptables rule to drop traffic received on that interface

set -e

NUM_IFACES=$(ls -A /sys/class/net | wc -l)
# account for loopback interface
NUM_IFACES=$((NUM_IFACES - 1))

for (( i = 0; i < NUM_IFACES; i++ )); do
    ip addr flush dev eth$i
    iptables-nft -A INPUT -i eth$i -j DROP
done
iptables-nft -A FORWARD -j DROP

echo "network configured"
sleep infinity
