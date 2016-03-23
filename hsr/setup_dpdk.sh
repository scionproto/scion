#!/bin/sh

sudo ip link set dev eth1 down
sudo ip link set dev eth2 down

sudo $RTE_SDK/tools/dpdk_nic_bind.py --bind=igb_uio eth1
sudo $RTE_SDK/tools/dpdk_nic_bind.py --bind=igb_uio eth2
