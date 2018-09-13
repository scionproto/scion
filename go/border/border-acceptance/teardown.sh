#!/bin/bash

sudo ip link set veth0_dock down
sudo ip link set veth0_root down
sudo ip link del veth0_root
sudo ip link set veth1_dock down
sudo ip link set veth1_root down
sudo ip link del veth1_root
docker-compose -f docker-compose.yml -f br-compose.yml down
sudo rm -f /var/run/netns/*
