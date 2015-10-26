#!/usr/bin/python2

from mininet.net import Mininet
from mininet.node import OVSKernelSwitch
from mininet.topo import Topo
from mininet.log import lg
from mininet.cli import CLI
import configparser
import ipaddress

import sys
flush = sys.stdout.flush


class ScionTopo(Topo):
    """
    Topology built from a SCION mininet config."
    """

    def __init__(self, mnconfig, **params):

        # Initialize topology
        Topo.__init__(self, **params)

        counter = 1
        for section in mnconfig.sections():
            hosts = dict(mnconfig.items(section))
            if(len(hosts) > 2):
                switchname = self.addSwitch('s'+str(counter))
                counter = counter + 1
                hostcounter = 1
                for name, hostip in hosts.items():
                    hostip = ipaddress.IPv4Interface(hostip).with_prefixlen
                    myhost = self.addHost(name, ip=str(hostip))
                    ifName1 = 'h' + str(counter) + str(hostcounter)
                    ifName2 = 'net' + str(counter) + str(hostcounter)
                    # be careful when assigning interface names manually, since
                    # they must be unique across the entire topology.
                    # also btw, the zookeper links orders get flipped because
                    # mininet, so the zk nodes end up with intfName2 instead of
                    # intfName1.
                    self.addLink(myhost, switchname, intfName1=ifName1,
                                 intfName2=ifName2)
                    hostcounter = hostcounter + 1
        for section in mnconfig.sections():
            hosts = dict(mnconfig.items(section))
            if(len(hosts) == 2):
                switchname = self.addSwitch('s'+str(counter))
                counter = counter + 1
                hostcounter = 1
                for name, hostip in hosts.items():
                    hostip = ipaddress.IPv4Interface(hostip).with_prefixlen
                    ifName1 = 'wan' + str(counter) + str(hostcounter)
                    ifName2 = 'er' + str(counter) + str(hostcounter)
                    self.addLink(name, switchname, intfName1=ifName1,
                                 intfName2=ifName2, params1={'ip': str(hostip)})
                    hostcounter = hostcounter + 1

if __name__ == '__main__':
    lg.setLogLevel('info')
    topology = configparser.ConfigParser(interpolation=None)
    topology.read('../gen/networks.conf')
    topo = ScionTopo(topology)
    net = Mininet(topo=topo, switch=OVSKernelSwitch)
    net.start()
    # net.pingAll()
    CLI = CLI(net)
    # flush()
    net.stop()
