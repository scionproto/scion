#!/usr/bin/python2

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, Controller
from mininet.topo import Topo
from mininet.log import lg
from mininet.link import Link
from mininet.cli import CLI
import configparser
import ipaddress
import os

if os.environ.has_key('SUDO_USER'):
        USER = os.environ['SUDO_USER']
else:
        USER = os.environ['USER']

MAX_INTF_LEN = 15
NETWORKS_CONF = "gen/networks.conf"

class ScionLink(Link):
    @classmethod
    def intfName(cls, node, n):
        # Override the default intf naming in Link, as the default "NAME-ethX"
        # form becomes too long.
        name = "%s-%s" % (node.name, n)
        assert len(name) <= MAX_INTF_LEN
        return name


class POXController( Controller ):
    "A locally installed POX controller"
    poxBin='/home/'+USER+'/.local/bin/pox'
    poxArgs='openflow.of_01 --port=%d forwarding.l2_learning'
    def __init__( self, name, command=poxBin, cargs=poxArgs, **kwargs ):
        Controller.__init__( self, name, command=command, cargs=cargs,
                            **kwargs )


class ScionTopo(Topo):
    """
    Topology built from a SCION network config."
    """
    def __init__(self, mnconfig, **params):

        # Initialize topology
        Topo.__init__(self, **params)
        self._genTopo(mnconfig)

    def _genTopo(self, mnconfig):
        switch_map = {}
        for i, name in enumerate(mnconfig.sections()):
            switch_map[name] = self.addSwitch("s%s" % i)
        host_map = {}
        for name, section in mnconfig.items():
            for elem, intf_str in section.items():
                # The config is utf8, need to convert to a plain string to avoid
                # tickling bugs in mininet.
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
        # Map the supplied params to the node1 interface, even if sorting turns
        # it into the second interface.
        if key[0] == node1:
            self.link_info[key] = {"params1": params}
        else:
            self.link_info[key] = {"params2": params}
        self.g.add_edge(*key)
        return key


def main():
    lg.setLogLevel('info')
    topology = configparser.ConfigParser(interpolation=None)
    topology.read_file(open(NETWORKS_CONF), source=NETWORKS_CONF)
    topo = ScionTopo(topology)
    net = Mininet(topo=topo, controller=POXController, link=ScionLink,
                  switch=OVSKernelSwitch)
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()
