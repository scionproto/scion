# Preparations

## Additional packages
You will need to install the following packages:
```
sudo apt-get install hugepages sysfsutils libmnl-dev libpcap-dev bridge-utils
```

## Hugepages
Setup hugepages as follows:
```
sudo bash -c 'echo "kernel/mm/hugepages/hugepages-2048kB/nr_hugepages = 256" > /etc/sysfs.d/hugepages.conf'
sudo service sysfsutils restart
sudo bash -c 'echo "nodev /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab'
HUGEPAGE_MOUNT=/mnt/huge
sudo mkdir $HUGEPAGE_MOUNT
sudo mount $HUGEPAGE_MOUNT
```

## DPDK
This library requires DPDK 16.07 to be downloaded and built on the machine.

Download DPDK source code:
```
wget http://fast.dpdk.org/rel/dpdk-16.07.tar.xz
tar xf dpdk-16.07.tar.xz
```

Build DPDK:
```
cd dpdk-16.07
export RTE_SDK=`pwd`
export RTE_TARGET=x86_64-native-linuxapp-gcc
make config T=$RTE_TARGET
sed -i '/CONFIG_RTE_LIBRTE_PMD_PCAP=n/c\CONFIG_RTE_LIBRTE_PMD_PCAP=y' $RTE_SDK/build/.config
sed -i '/CONFIG_RTE_BUILD_SHARED_LIB=n/c\CONFIG_RTE_BUILD_SHARED_LIB=y' $RTE_SDK/build/.config
make -j2
make -j2 install T=$RTE_TARGET
```

Setup DPDK drivers:
```
sudo modprobe uio
sudo insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko
sudo insmod $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko
sudo ln -s $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko /lib/modules/`uname -r`
sudo ln -s $RTE_SDK/$RTE_TARGET/kmod/rte_kni.ko /lib/modules/`uname -r`
sudo depmod -a
echo "uio" | sudo tee -a /etc/modules
echo "igb_uio" | sudo tee -a /etc/modules
echo "rte_kni" | sudo tee -a /etc/modules
```

Add envvars to .profile so that they are set on login
```
echo "export RTE_SDK=$RTE_SDK" >> $HOME/.profile
echo "export RTE_TARGET=$RTE_TARGET" >> $HOME/.profile
```

## Network setup
This library assumes a bridge interface is setup for each NIC used by the HSR, named br0, br1, etc.
Before HSR is run, each bridge interface should be connected to a NIC and configured with the proper IP/MAC addresses.
See the included file "interfaces" for an example of such network configuration.


# Building

## Building libhsr
Libhsr is built as a static library. From scion base directory:
```
make libhsr
```
This builds the library at lib/libhsr/build/lib

## Linking against libhsr
In addition to libhsr.a, you must also link libmnl and libdpdk, for example:
```
LDFLAGS += -L$(RTE_SDK)/build/lib -ldpdk -lmnl
```


# Running

## Library path
To run HSR, LD_LIBRARY_PATH must contain $RTE_SDK/build/lib

## DPDK drivers
Any NICs to be used with DPDK must be bound to the igb_uio driver before running HSR. To see a list of devices and their status (managed by DPDK/kernel):
```
$RTE_SDK/tools/dpdk-devbind.py --status
```
These interfaces should have their kernel drivers restored upon termination of HSR.

## Example
The included file "exec_dpdk.sh" shows an example of setting up and running HSR.
