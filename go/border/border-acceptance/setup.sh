#!/bin/bash

#set -x

OUTPUT_FN=$2
rm -f $OUTPUT_FN

# syntax: create_veth <host_if_name> <container_if_name> <container_ip_addr> <neigh_ips>
function create_veth {
    VETH_HOST=$1
    VETH_CONTAINER=$2
    IP_CONTAINER=$3
    shift 3
    # Set veth1 pair
    sudo ip link add ${VETH_HOST} type veth peer name ${VETH_CONTAINER}
    sudo sysctl -w net.ipv6.conf.${VETH_HOST}.disable_ipv6=1
    sudo ip link set ${VETH_HOST} up
    sudo ip link set ${VETH_CONTAINER} netns $NS
    sudo ip netns exec $NS sysctl -w net.ipv6.conf.${VETH_CONTAINER}.disable_ipv6=1
    sudo ip netns exec $NS ip addr add ${IP_CONTAINER} dev ${VETH_CONTAINER}
    for ip in "$@"; do
        sudo ip netns exec $NS ip neigh add $ip lladdr f0:0d:ca:fe:be:ef nud permanent dev ${VETH_CONTAINER}
    done
    sudo ip netns exec $NS ip link set ${VETH_CONTAINER} up
    MAC=`sudo ip netns exec $NS cat /sys/class/net/${VETH_CONTAINER}/address`
    echo "${VETH_HOST} ${VETH_CONTAINER} $MAC" >> ${OUTPUT_FN}
}

# Bring up the dispatcher container and add new veth interfaces
# This works because dispatcher binds to 0.0.0.0 address.
#docker-compose -f docker-compose.yml -f br-compose.yml up --no-start
# XXX It looks like if we do not have both compose.yml files at this point,
# when later starting the border docker container, it creates a NEW namespace
# dropping all the setup we just did!

docker-compose -f docker-compose.yml up --detach dispatcher

# Add dispatcher network namespace link to be use with ip netns tool
NS_path=`docker inspect border-acceptance_dispatcher_1 -f '{{.NetworkSettings.SandboxKey}}'`
echo "Docker namespace ID full path: $NS_path"
sudo mkdir -p /var/run/netns && sudo ln -fs $NS_path -t /var/run/netns
mkdir -p netns && ln -fs $NS_path -t netns
NS=`ip netns list`
echo "Docker namespace ID $NS"

infra_as1="192.168.0.51 192.168.0.61 192.168.0.71"
infra_as4="192.168.0.51 192.168.0.61 192.168.0.71"
case $1 in
    core-brA)
        create_veth veth0_root ifid_local 192.168.0.11/24 192.168.0.12 192.168.0.13 $infra_as1
        create_veth veth1_root ifid_1201 192.168.12.2/31 192.168.12.3
        ;;
    core-brB)
        create_veth veth0_root ifid_local 192.168.0.12/24 192.168.0.11 192.168.0.13 $infra_as1
        create_veth veth1_root ifid_1301 192.168.13.2/31 192.168.13.3
        create_veth veth2_root ifid_1401 192.168.14.2/31 192.168.14.3
        create_veth veth3_root ifid_1402 192.168.14.4/31 192.168.14.5
        ;;
    core-brC)
        create_veth veth0_root ifid_local 192.168.0.13/24 192.168.0.11 192.168.0.12 $infra_as1
        create_veth veth2_root ifid_1501 192.168.15.2/31 192.168.15.3
        ;;
    brA)
        create_veth veth0_root ifid_local 192.168.0.11/24 192.168.0.12 192.168.0.13 192.168.0.14 $infra_as4
        create_veth veth1_root ifid_4101 192.168.41.2/31 192.168.41.3
        create_veth veth2_root ifid_4201 192.168.42.2/31 192.168.42.3
        create_veth veth3_root ifid_4801 192.168.48.4/31 192.168.48.5
        create_veth veth4_root ifid_4601 192.168.46.2/31 192.168.46.3
        create_veth veth5_root ifid_4701 192.168.47.2/31 192.168.47.3
        ;;
    brB)
        create_veth veth0_root ifid_local 192.168.0.12/24 192.168.0.11 192.168.0.13 192.168.0.14 $infra_as4
        create_veth veth1_root ifid_4102 192.168.41.4/31 192.168.41.5
        ;;
    brC)
        create_veth veth0_root ifid_local 192.168.0.13/24 192.168.0.11 192.168.0.12 192.168.0.14 $infra_as4
        create_veth veth1_root ifid_4102 192.168.45.4/31 192.168.41.5
        ;;
    brD)
        create_veth veth0_root ifid_local 192.168.0.14/24 192.168.0.11 192.168.0.12 192.168.0.13 $infra_as4
        create_veth veth1_root ifid_4102 192.168.46.5/31 192.168.46.6
        ;;
    *)
        echo "ERROR: Unknown Border Router ID"
        ./teardown.sh
        exit 1
esac

docker-compose -f docker-compose.yml up --detach $1
