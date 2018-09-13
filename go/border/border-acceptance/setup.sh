#!/bin/bash

# Bring up the dispatcher container and add new veth interfaces
# This works because dispatcher binds to 0.0.0.0 address.
#docker-compose -f docker-compose.yml -f br-compose.yml up --no-start
# XXX It looks like if we do not have both compose.yml files at this point,
# when later starting the border docker container, it creates a NEW namespace
# dropping all the setup we just did!
docker-compose -f docker-compose.yml -f br-compose.yml up --detach dispatcher
# Add dispatcher network namespace link to be use with ip netns tool
sudo mkdir -p /var/run/netns
sudo ln -fs `docker inspect border-acceptance_dispatcher_1 -f '{{.NetworkSettings.SandboxKey}}'` -t /var/run/netns
NS=`ip netns list`
echo "Docker namespace ID $NS"
# Set veth0 pair - internal/local br network
sudo ip link add veth0_root type veth peer name ifid_local
sudo sysctl -w net.ipv6.conf.veth0_root.disable_ipv6=1
sudo ip link set veth0_root up
sudo ip link set ifid_local netns $NS
sudo ip netns exec $NS sysctl -w net.ipv6.conf.ifid_local.disable_ipv6=1
sudo ip netns exec $NS ip addr add 192.168.0.11/24 dev ifid_local
sudo ip netns exec $NS ip neigh add 192.168.0.51 lladdr f0:0d:ca:fe:be:ef nud permanent dev ifid_local
sudo ip netns exec $NS ip neigh add 192.168.0.61 lladdr f0:0d:ca:fe:be:ef nud permanent dev ifid_local
sudo ip netns exec $NS ip neigh add 192.168.0.71 lladdr f0:0d:ca:fe:be:ef nud permanent dev ifid_local
sudo ip netns exec $NS ip link set ifid_local up
MAC=`sudo ip netns exec $NS cat /sys/class/net/ifid_local/address`
echo "veth0_root ifid_local $MAC" > info.txt
# Set veth1 pair
sudo ip link add veth1_root type veth peer name ifid_1201
sudo sysctl -w net.ipv6.conf.veth1_root.disable_ipv6=1
sudo ip link set veth1_root up
sudo ip link set ifid_1201 netns $NS
sudo ip netns exec $NS sysctl -w net.ipv6.conf.ifid_1201.disable_ipv6=1
sudo ip netns exec $NS ip addr add 192.168.12.3/24 dev ifid_1201
sudo ip netns exec $NS ip neigh add 192.168.12.4 lladdr f0:0d:ca:fe:be:ef nud permanent dev ifid_1201
sudo ip netns exec $NS ip link set ifid_1201 up
MAC=`sudo ip netns exec $NS cat /sys/class/net/ifid_1201/address`
echo "veth1_root ifid_1201 $MAC" >> info.txt
#
printf "\nHOST\n"; ip a
printf "\nDOCKER\n"; sudo ip netns exec $NS ip a
printf "\nDOCKER neighbours\n"; sudo ip netns exec $NS ip neigh
# Bring up the border router container
#docker-compose -f docker-compose.yml -f br-compose.yml start --detach
docker-compose -f docker-compose.yml -f br-compose.yml up --detach border


exit


sudo rm -f /var/run/netns/$NS
sudo ln -fs `docker inspect border-acceptance_dispatcher_1 -f '{{.NetworkSettings.SandboxKey}}'` -t /var/run/netns
NS=`ip netns list`
echo "Docker namespace ID $NS"
sudo ip netns exec $NS ip a
sudo ip netns exec $NS ip neigh
