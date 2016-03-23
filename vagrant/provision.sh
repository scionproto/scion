#!/bin/sh
#
# This script downloads, installs and configure the Intel DPDK framework
# on a clean Ubuntu 14.04 installation running in a virtual machine.
# 
# This script has been created based on the following scripts:
#  * https://gist.github.com/ConradIrwin/9077440
#  * http://dpdk.org/doc/quick-start

# Configure hugepages
# You can later check if this change was successful with "cat /proc/meminfo"
# Hugepages setup should be done as early as possible after boot
# Note: hugepages setup does not persist across reboots

# Use local Ubuntu mirror
sudo bash -c 'cat << EOF > /etc/apt/sources.list
deb mirror://mirrors.ubuntu.com/mirrors.txt trusty main restricted universe multiverse
deb mirror://mirrors.ubuntu.com/mirrors.txt trusty-updates main restricted universe multiverse
deb mirror://mirrors.ubuntu.com/mirrors.txt trusty-backports main restricted universe multiverse
deb mirror://mirrors.ubuntu.com/mirrors.txt trusty-security main restricted universe multiverse
EOF'

# Install dependencies
sudo apt-get update
sudo apt-get -y -q install git clang doxygen hugepages build-essential\
    linux-headers-`uname -r` yasm wget python3-pip sysfsutils libcurl4-openssl-dev
sudo pip3 install pyyaml

sudo bash -c 'echo "kernel/mm/hugepages/hugepages-2048kB/nr_hugepages = 256" > /etc/sysfs.d/hugepages.conf'
sudo service sysfsutils restart
sudo bash -c 'echo "nodev /mnt/huge hugetlbfs defaults 0 0" >> /etc/fstab'
HUGEPAGE_MOUNT=/mnt/huge
sudo mkdir ${HUGEPAGE_MOUNT}
sudo mount ${HUGEPAGE_MOUNT}
 
# Get code from Git repo
#git clone http://dpdk.org/git/dpdk
wget http://dpdk.org/browse/dpdk/snapshot/dpdk-2.0.0.tar.gz
tar xvzf dpdk-2.0.0.tar.gz

# Move to the DPDK dir
cd dpdk-2.0.0

# Path to the build dir
export RTE_SDK=`pwd`

# Target of build process
export RTE_TARGET=x86_64-native-linuxapp-gcc

# Build code
# I am building from the dev branch (plus POPCNT patch) because the latest stable release
# at the time of writing this script (1.7.0) has a bug preventing DPDK compilation on Ubuntu 14.04
make config T=${RTE_TARGET}
make -j2

# Install kernel modules
sudo modprobe uio
sudo insmod ${RTE_SDK}/build/kmod/igb_uio.ko

# Make uio and igb_uio installations persist across reboots 
sudo ln -s ${RTE_SDK}/build/kmod/igb_uio.ko /lib/modules/`uname -r`
sudo depmod -a
echo "uio" | sudo tee -a /etc/modules
echo "igb_uio" | sudo tee -a /etc/modules

# Add env variables setting to .profile file so that they are set at each login
echo "export RTE_SDK=${RTE_SDK}" >> ${HOME}/.profile
echo "export RTE_TARGET=${RTE_TARGET}" >> ${HOME}/.profile

# We need to do this to make the examples compile, not sure why.
ln -s ${RTE_SDK}/build ${RTE_SDK}/${RTE_TARGET}


