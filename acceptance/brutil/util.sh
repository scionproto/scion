# This is a base file included/sourced by each border router acceptance test

# Following are the specific setup functions for border acceptance tests

# Syntax:
#  create_veth <host_if_name> <container_if_name> <container_ip_addr> <container_mac_addr> <neigh_ips>
create_veth() {
    VETH_HOST=${1:?}
    VETH_CONTAINER=${2:?}
    IP_CONTAINER=${3:?}
    MAC_CONTAINER=${4:?}
    shift 4
    NS=$(get_docker_ns)
    # Set veth1 pair
    sudo ip link add $VETH_HOST mtu 8000 type veth peer name $VETH_CONTAINER mtu 8000
    sudo sysctl -qw net.ipv6.conf.$VETH_HOST.disable_ipv6=1
    sudo ip link set $VETH_HOST up
    sudo ip link set $VETH_CONTAINER netns $NS
    sudo ip netns exec $NS sysctl -qw net.ipv6.conf.$VETH_CONTAINER.disable_ipv6=1
    sudo ip netns exec $NS ethtool -K $VETH_CONTAINER rx off tx off 1>&2
    sudo ip netns exec $NS ip link set $VETH_CONTAINER address $MAC_CONTAINER
    sudo ip netns exec $NS ip addr add $IP_CONTAINER dev $VETH_CONTAINER
    for ip in "$@"; do
        sudo ip netns exec $NS ip neigh add $ip lladdr f0:0d:ca:fe:be:ef nud permanent dev $VETH_CONTAINER
    done
    sudo ip netns exec $NS ip link set $VETH_CONTAINER up
}

get_docker_ns_path() {
    docker inspect brutil_dispatcher_1 -f '{{.NetworkSettings.SandboxKey}}'
}

get_docker_ns() {
    NS_path=$(get_docker_ns_path)
    basename ${NS_path:?}
}

set_docker_ns_link() {
    NS_path=$(get_docker_ns_path)
    sudo mkdir -p /var/run/netns && sudo ln -t /var/run/netns -fs ${NS_path:?}
}

rm_docker_ns_link() {
    NS=$(get_docker_ns)
    sudo rm -f /var/run/netns/${NS:?}
}

delete_veth() {
    for dev in "$@"; do
        sudo ip link set $dev down && sudo ip link del $dev || true
    done
}

