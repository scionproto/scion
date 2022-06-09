#!/bin/bash
set -ex

NETWORK=$1
RATE=$2

veths=$(brctl show $NETWORK | awk 'NR>1''{print $NF}')
for veth in $veths
do
    echo $veth
    tc qdisc add dev $veth root tbf rate $RATE latency 1ms burst 50kb mtu 10000
done
