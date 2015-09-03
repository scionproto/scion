#High-speed Router

High-speed router (HSR) is an implementation of SCION router using Intel DPDK.
The goal of this project is demonstration of the performance (high toroughput and low latency).


## Install
1. Install Intel DPDK.
2. "make" in the hsr directory.

## Run
'sudo ./build/hsr -c 0xf -n 4 -- -p 0xf -T 0'
  
The parameters depend on your machine and DPDK configurations.
Please see [Getting Started Guide](http://dpdk.org/doc/guides-2.0/linux_gsg/index.html)
