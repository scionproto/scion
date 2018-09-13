#!/bin/bash

sudo ip link set veth0_root down
sudo ip link del veth0_root
sudo ip link set veth1_root down
sudo ip link del veth1_root
docker-compose -f docker-compose.yml down
for fn in netns/*; do
    f=$(basename -- $fn)
    sudo rm -f /var/run/netns/$f
    rm -f netns/$f
done
