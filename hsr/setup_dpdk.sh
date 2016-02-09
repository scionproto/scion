#!/bin/sh

#echo 1024 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
echo 256 | sudo tee /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
sudo mkdir /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

sudo ifconfig eth1 down
sudo ifconfig eth2 down

sudo $RTE_SDK/tools/dpdk_nic_bind.py --bind=igb_uio eth1
sudo $RTE_SDK/tools/dpdk_nic_bind.py --bind=igb_uio eth2
