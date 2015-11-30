#High-speed Router

High-speed router (HSR) is an implementation of SCION router using Intel DPDK.
The goal of this project is demonstration of the performance (high toroughput and low latency).

## Prerequisites
* [NICs supported by DPDK](http://dpdk.org/doc/nics)
* CPU with AES-NI
* [DPDK version 2.0] (http://dpdk.org/browse/dpdk/refs/)


## Install
1. [Install Intel DPDK 2.0.](http://dpdk.org/doc/guides/linux_gsg/index.html)
2. "make" in the hsr directory.

## Run
'sudo ./build/hsr -c COREMASK -n NUMBER_OF_MEMORY_CHANNELS -- -p PORTMASK -T 0 ROUTER_NAME PATH_TO_TOPOLOGY_FILE PATH_TO_AD_CONF_FILE'

For exampke,  
sudo ./build/hsr -c 0x3 -n 4 -- -p 0xf -T 0 er1-10er1-19 ../gen/ISD1/AD10/er1-10er1-19/topology.conf ../gen/ISD1/AD10/er1-10er1-19/ad.conf
  
The parameters depend on your machine and DPDK configurations.
Please see [Getting Started Guide](http://dpdk.org/doc/guides-2.0/linux_gsg/index.html)
