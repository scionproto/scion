#!/bin/bash
set -ex
 # Configure reverse path filter
sysctl -w net.ipv4.conf.all.rp_filter=0
sysctl -w net.ipv4.conf.default.rp_filter=0
 # Configure IP Forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
 # Register SIG routing table
echo "11 sig" > /etc/iproute2/rt_tables
for net in $(echo $1 | tr , ' '); do
    ip rule add to "$net" lookup sig
done

shift
/sbin/su-exec /app/sig -config conf/sig.toml
