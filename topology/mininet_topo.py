#!/usr/bin/python2

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.topo import Topo
from mininet.log import lg
from mininet.link import Link
from mininet.cli import CLI
import configparser
import ipaddress

MAX_INTF_LEN = 15


class ScionLink(Link):
    @classmethod
    def intfName(cls, node, n):
        name = "%s-%s" % (node.name, n)
        assert len(name) <= MAX_INTF_LEN
        return name


class ScionTopo(Topo):
    """
    Topology built from a SCION mininet config."
    """

    def __init__(self, mnconfig, **params):

        # Initialize topology
        Topo.__init__(self, **params)

        switch_map = {}
        for i, name in enumerate(mnconfig.sections()):
            switch_map[name] = self.addSwitch("s%s" % i)
        host_map = {}
        for name, section in mnconfig.items():
            for elem, intf_str in section.items():
                elem = str(elem)
                if elem not in host_map:
                    host_map[elem] = self.addHost(
                        elem.replace("-", "_"), ip=None)
                intf = ipaddress.ip_interface(intf_str)
                self.addLink(host_map[elem], switch_map[name],
                             params={'ip': str(intf)})

    def addLink(self, node1, node2, params=None):
        self.addPort(node1, node2, None, None)
        key = tuple(self.sorted([node1, node2]))
        if key[0] == node1:
            self.link_info[key] = {"params1": params}
        else:
            self.link_info[key] = {"params2": params}
        self.g.add_edge(*key)
        return key


if __name__ == '__main__':
    lg.setLogLevel('info')
    topology = configparser.ConfigParser(interpolation=None)
    topology.read('gen/networks.conf')
    topo = ScionTopo(topology)
    net = Mininet(topo=topo, controller=RemoteController, link=ScionLink,
                  switch=OVSKernelSwitch)
    net.start()
    CLI = CLI(net)
    net.stop()
