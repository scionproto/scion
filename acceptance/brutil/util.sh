#!/bin/bash

# syntax: create_veth <netns> <host_if_name> <container_if_name> <container_ip_addr> <neigh_ips>
create_veth() {
    NS=$1
    VETH_HOST=$2
    VETH_CONTAINER=$3
    IP_CONTAINER=$4
    shift 4
    # Set veth1 pair
    sudo ip link add $VETH_HOST type veth peer name $VETH_CONTAINER
    sudo sysctl -qw net.ipv6.conf.$VETH_HOST.disable_ipv6=1
    sudo ip link set $VETH_HOST up
    sudo ip link set $VETH_CONTAINER netns $NS
    sudo ip netns exec $NS sysctl -qw net.ipv6.conf.$VETH_CONTAINER.disable_ipv6=1
    sudo ip netns exec $NS ip addr add $IP_CONTAINER dev $VETH_CONTAINER
    for ip in "$@"; do
        sudo ip netns exec $NS ip neigh add $ip lladdr f0:0d:ca:fe:be:ef nud permanent dev $VETH_CONTAINER
    done
    sudo ip netns exec $NS ip link set $VETH_CONTAINER up
	MAC=$(sudo ip netns exec $NS cat /sys/class/net/${VETH_CONTAINER}/address)
    echo "$VETH_HOST $VETH_CONTAINER $MAC"
}

get_docker_ns_path() {
    echo $(docker inspect brutil_dispatcher_1 -f '{{.NetworkSettings.SandboxKey}}')
}

get_docker_ns() {
	NS_path=$(get_docker_ns_path)
	echo $(basename $NS_path)
}

set_docker_ns_link() {
	NS_path=$(get_docker_ns_path)
    sudo mkdir -p /var/run/netns && sudo ln -fs $NS_path -t /var/run/netns
}

rm_docker_ns_link() {
	NS=$(get_docker_ns)
    sudo rm -f /var/run/netns/$NS
}

delete_veth() {
    for dev in "$@"; do
        sudo ip link set $dev down && sudo ip link del $dev || true
    done
}
