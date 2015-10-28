#!/usr/bin/python2
# Copyright 2015 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Stdlib
import configparser
import ipaddress
import sys
import os.path

# External packages
from mininet.net import Mininet
from mininet.node import OVSKernelSwitch, OVSController
from mininet.topo import Topo
from mininet.log import lg
from mininet.cli import CLI


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


def runMininet():
    lg.setLogLevel('info')
    topology = configparser.ConfigParser(interpolation=None)
    if os.path.isfile('../gen/networks.conf'):
        topology.read('../gen/networks.conf')
        # should also check if this is a 127.0.x.x file, or a 100.64.x.x
        if (ipaddress.IPv4Interface(topology.sections()[0]).is_loopback):
            sys.exit(-1)
    else:
        sys.exit(-1)

    topo = ScionTopo(topology)
    net = Mininet(topo=topo, switch=OVSKernelSwitch, controller=OVSController)
    net.start()
    # net.pingAll()
    CLI(net)
    # flush()
    net.stop()

if __name__ == '__main__':
    runMininet()
