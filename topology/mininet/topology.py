#!/usr/bin/python2

# Stdlib
import os
import sys

# External
import configparser
import ipaddress
from mininet.cli import CLI
from mininet.link import Link
from mininet.log import lg
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.topo import Topo

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


class ScionTopo(Topo):
    """
    Topology built from a SCION network config."
    """
    def __init__(self, mnconfig, **params):

        # Initialize topology
        Topo.__init__(self, **params)
        self.switch_map = {}
        self._genTopo(mnconfig)

    def _genTopo(self, mnconfig):
        for i, name in enumerate(mnconfig.sections()):
            self.switch_map[name] = self.addSwitch("s%s" % i)
        host_map = {}
        for name, section in mnconfig.items():
            for elem, intf_str in section.items():
                if ipaddress.ip_interface(intf_str).is_loopback:
                    print("The IP address for %s (%s) is a loopback address"
                          % (elem, intf_str))
                    print("Try running scion.sh topology -m")
                    sys.exit(1)
                # The config is utf8, need to convert to a plain string to avoid
                # tickling bugs in mininet.
                elem = str(elem)
                elem_name = elem.replace("-", "_")
                if elem not in host_map:
                    host_map[elem] = self.addHost(elem_name, ip=None)
                intf = ipaddress.ip_interface(intf_str)
                is_link = False
                if intf.network.prefixlen == intf.max_prefixlen - 1:
                    is_link = True
                self.addLink(
                    host_map[elem], self.switch_map[name],
                    params={'ip': str(intf)},
                    intfName="%s-%d" % (elem_name, is_link),
                )

    def addLink(self, node1, node2, params=None, intfName=None):
        self.addPort(node1, node2, None, None)
        key = tuple(self.sorted([node1, node2]))
        # Map the supplied params to the node1 interface, even if sorting turns
        # it into the second interface.
        if key[0] == node1:
            self.link_info[key] = {"params1": params, "intfName1": intfName}
        else:
            self.link_info[key] = {"params2": params, "intfName2": intfName}
        self.g.add_edge(*key)
        return key


def main():
    lg.setLogLevel('info')
    supervisord = os.getenv("SUPERVISORD")
    assert supervisord
    topology = configparser.ConfigParser(interpolation=None)
    topology.read_file(open(NETWORKS_CONF), source=NETWORKS_CONF)
    topo = ScionTopo(topology)
    net = Mininet(topo=topo, controller=RemoteController, link=ScionLink,
                  switch=OVSKernelSwitch)
    for host in net.hosts:
        host.cmd('ip route add 169.254.0.0/16 dev '+host.intf().name)
    net.start()
    os.system('ip addr add 169.254.0.1/16 dev eth0')
    for switch in net.switches:
        for k, v in topo.switch_map.items():
            if v == switch.name:
                os.system('ip route add %s dev %s' % (k, switch.name))
    for host in net.hosts:
        elem_name = host.name.replace("_", "-")
        print("Starting supervisord on %s" % elem_name)
        host.cmd("%s -c gen/mininet/%s.conf" % (supervisord, elem_name))
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()
