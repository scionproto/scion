# SCION on Mininet

SCION can be run inside [Mininet](http://mininet.org), which is a virtual network emulation environment. Running SCION in Mininet enables the use of custom topologies and link characteristics (e.g., specifying link bandwidth between two ASes).

## Getting started
We currently support only Mininet 2.1.0 installed from the Ubuntu 14.04 repositories. As a result, you will need kernel 3.x. If you have kernel 4.2 (check the output of "uname -r") you will need to follow the instructions in the "Installing kernel 3.x" section below.

### Installing kernel 3.x
Run the following command to install kernel 3.x:
```
sudo apt-get install linux-image-generic-lts-trusty
```
Edit /etc/default/grub as root so that the first section looks like the example below:
```
GRUB_DEFAULT=2
#GRUB_HIDDEN_TIMEOUT=0
#GRUB_HIDDEN_TIMEOUT_QUIET=true
GRUB_TIMEOUT=10
GRUB_DISTRIBUTOR=`lsb_release -i -s 2> /dev/null || echo Debian`
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"
GRUB_CMDLINE_LINUX=""
GRUB_DISABLE_SUBMENU=y
```
and then run update-grub:
```
sudo update-grub
```
When you reboot, you will be taken into the GRUB menu. The kernel version you installed should be the one selected by default. However, the list can change in the future if, for example, you install kernel updates. In this case you will need to update /etc/default/grub to reflect the new list.

### Required packages
Due to the limited number of switches (16) supported by `openvswitch-controller`, we also require the use of a custom OpenFlow controller, [POX](http://www.noxrepo.org/pox/about-pox). The list of required packages can be found [here](pkgs_debian.txt) for manual installation or installed automatically using the [setup.sh](setup.sh) script we provide. Once you have all packages installed, you're ready to run SCION.

### Creating a Mininet-compatible topology
You need to generate a topology with Mininet support enabled. To do this, run the following command:
```
user@ubuntu:~/scion$ ./scion.sh topology -m
```
### Running the network
Now run the network:
```
user@ubuntu:~/scion$ topology/mininet/run.sh
```
You'll be dropped into a Mininet shell where you can list the nodes (`nodes`), show the topology (`net`), or launch xterms on one of the hosts (`xterm bs1_11_1`). You can also run commands directly on the hosts (`bs1_11_1 tcpdump -ni any`).

Once you're done looking around, you can type Ctrl+D to shutdown the Mininet environment. If something goes wrong and you have leftover network interfaces, you can clean them up by running
```
user@ubuntu:~/scion$ sudo mn -c
```
