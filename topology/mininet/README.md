# SCION on Mininet

SCION can be run inside [Mininet](http://mininet.org), which is a virtual network emulation environment. Running SCION in Mininet enables the use of custom topologies and link characteristics (e.g., specifying link bandwidth between two ASes). 

## Getting started
You'll need a few base packages to get started. We currently support only Mininet 2.1.0 installed from the Ubuntu 14.04 repositories. Due to limitations of in the number of switches that can exist in a single topology, we also require the use of a custom OpenVSwitch controller (POX). The list of required packages can be found [here](https://github.com/netsec-ethz/scion/blob/mininet/topology/mininet/pkgs_debian.txt) for manual installation or installed automatically using the [setup.sh](https://github.com/netsec-ethz/scion/blob/mininet/topology/mininet/setup.sh) script we provide. Once you have all packages installed, you're ready to run SCION.

### Creating a Mininet-compatible topology
You'll export the base SCION topology into a format that can be read by Mininet. To do this run the following command:
```
user@ubuntu:~/scion$ ./scion.sh topology -m
```
### Running the network
Now run the network:
```
user@ubuntu:~/scion$ topology/mininet/run.sh
```
You'll be dropped into a Mininet shell where you can list the nodes (```nodes```), show the topology (```net```), or launch xterms on one of the hosts (```xterm bs1_11_1```). You can also run commands directly on the hosts (```bs1_11_1 tcpdump -ni any```). 

Once you're done looking around, you can type Ctrl+D to shutdown the Mininet environment. If something goes wrong and you have leftover network interfaces, you can clean them up by running
```
user@ubuntu:~/scion$ mn -c
```
