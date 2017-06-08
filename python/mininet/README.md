# SCION on Mininet

SCION can be run inside [Mininet](http://mininet.org), which is a virtual network emulation environment. Running SCION in Mininet enables the use of custom topologies and link characteristics (e.g., specifying link bandwidth between two ASes).

## Getting started
You'll need a few base packages to get started. We support Mininet 2.2.1 (available from the Ubuntu 16.04 repositories). Due to the limited number of switches (16) supported by `openvswitch-controller`, we also require the use of a custom OpenFlow controller, [POX](http://www.noxrepo.org/pox/about-pox). The list of required packages can be found [here](pkgs_debian.txt) for manual installation or installed automatically using the [setup.sh](setup.sh) script we provide. Once you have all packages installed, you're ready to run SCION.

### Creating a Mininet-compatible topology
You need to generate a topology with Mininet support enabled. To do this, run the following command:
```
user@ubuntu:~/scion$ ./scion.sh topology -m
```
### Running the network
Now run the network:
```
user@ubuntu:~/scion$ python/mininet/run.sh
```
You'll be dropped into a Mininet shell where you can list the nodes (`nodes`), show the topology (`net`), or launch xterms on one of the hosts (`xterm bs1_11_1`). You can also run commands directly on the hosts (`bs1_11_1 tcpdump -ni any`).

Once you're done looking around, you can type Ctrl+D to shutdown the Mininet environment. If something goes wrong and you have leftover network interfaces, you can clean them up by running
```
user@ubuntu:~/scion$ sudo mn -c
```

### Running inside docker
If you want to run the mininet network inside docker, you need to make sure docker is using the `--privileged` flag. You can specify it like this:
```
DOCKER_ARGS=--privileged ./docker.sh run
```
