IF1=enp0s8
IF2=enp0s9
BUS1=0000:00:08.0
BUS2=0000:00:09.0
DRIVER1=e1000
DRIVER2=e1000

sudo ip link set dev $IF1 down
sudo ip link set dev $IF2 down

sudo $RTE_SDK/tools/dpdk-devbind.py --bind=igb_uio $BUS1
sudo $RTE_SDK/tools/dpdk-devbind.py --bind=igb_uio $BUS2

GENPATH=../scion/gen/ISD1/AS11/br1-11-2

# Use first line for DPDK drivers, second line for libpcap drivers
sudo LD_LIBRARY_PATH=../scion/lib/hsr/build/lib ./hsr hsr.conf -c 0x1 -n 4 -- br1-11-2 $GENPATH/topology.yml $GENPATH/as.yml
#sudo ./build/hsr -c 0xf -n 4 -d librte_pmd_pcap.so --vdev='eth_pcap0,iface=$IF1' --vdev='eth_pcap1,iface=$IF2' -- br1-11-2 $GENPATH/topology.yml $GENPATH/as.yml

echo "Restore kernel drivers"
sudo $RTE_SDK/tools/dpdk-devbind.py -b $DRIVER1 $BUS1
sudo $RTE_SDK/tools/dpdk-devbind.py -b $DRIVER2 $BUS2
