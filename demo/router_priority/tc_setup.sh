#!/bin/bash
set -ex

NETWORK=$1
RATE=$2

veths=$(bridge link show | awk "/$NETWORK/{print \$2}")
for veth in $veths
do
    echo $veth
    tc qdisc add dev $veth root tbf rate $RATE latency 1ms burst 50kb mtu 10000
done
