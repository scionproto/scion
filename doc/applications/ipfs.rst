IPFS over SCION
=======================================

To benefit from SCION's security and reliability improvements compared to the traditional Internet, we are working on an `IPFS <https://github.com/ipfs/kubo>`_ implementation with SCION support.

The SCION Education Network will soon run some IPFS nodes including some content, and share the node addresses.

To setup IPFS over SCION on your node, follow these instructions. At first, download the proper binary from our `releases site <https://github.com/netsys-lab/sciera-releases/tree/main/ipfs/latest>`_.

Start some nodes by replacing {ISD-AS} with your ISD-AS combination and {IP} with your local IP (must be reachable within your SCION AS).
.. code-block:: console
    cd kubo
    mkdir ~/node1
    IPFS_PATH=~/node1 cmd/ipfs/ipfs init -p test
    IPFS_PATH=~/node1 cmd/ipfs/ipfs config --json Addresses.Swarm '["/scion/{ISD-AS},[{IP}]/udp/0/quic"]'
    IPFS_PATH=~/node1 cmd/ipfs/ipfs config --json Swarm.Transports.Network '{"QUIC": false, "SCIONQUIC": true}'
    IPFS_PATH=~/node1 cmd/ipfs/ipfs daemon --debug


Connect nodes
.. code-block:: console
    cd kubo
    IPFS_PATH=~/node1 cmd/ipfs/ipfs swarm connect `IPFS_PATH=~/node2 cmd/ipfs/ipfs id -f="<addrs>"`
```

As soon as all of our IPFS nodes in the network are running and serving content, we will announce their addresses here. You can then connect to them by replacing <addrs> in the previous command.