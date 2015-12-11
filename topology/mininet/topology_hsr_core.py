#!/usr/bin/python2

# Stdlib
import os
import sys

# External
import configparser
import ipaddress
from mininet.cli import CLI
from mininet.log import lg
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.link import Intf

MAX_INTF_LEN = 15
NETWORKS_CONF = "gen/networks.conf"

HSR = "er1_11er1_13"
HSR_EGRESS_IP = "100.64.0.2"
HSR_LOCAL_IP = "100.64.0.13"


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
                    print("""ERROR: The IP address for %s (%s) is a loopback
                          address""" % (elem, intf_str))
                    print("Try running scion.sh topology -m")
                    sys.exit(1)
                # The config is utf8, need to convert to a plain string to avoid
                # tickling bugs in mininet.
                elem = str(elem)
                elem_name = elem.replace("-", "_")
                if elem not in host_map:
                    # host_map[elem] = self.addHost(elem_name, ip=None)
                    host_map[elem] = self.addHost(elem_name, ip=None)
                intf = ipaddress.ip_interface(intf_str)
                is_link = False
                if intf.network.prefixlen == intf.max_prefixlen - 1:
                    is_link = True
                intfName = "%s-%d" % (elem_name, is_link)
                assert len(intfName) <= MAX_INTF_LEN
                self.addLink(
                    host_map[elem], self.switch_map[name],
                    params={'ip': str(intf)},
                    intfName=intfName,
                )

    def addLink(self, node1, node2, params=None, intfName=None):
        # sasaki disable er13, as HSR transfers packet instead of er13
        if node1 == "er1_11er1_13" or node2 == "er1_11er1_13":
            return

        self.addPort(node1, node2, None, None)
        key = tuple(self.sorted([node1, node2]))
        # if node2 == "s2":
        #    return
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
    net = Mininet(topo=topo, controller=RemoteController)

    for host in net.hosts:
        # static arp setting to send packets to HSR
        if host.name == "er1_13er1_11":
            host.setMAC("0:0:0:0:0:CC", "er1_13er1_11-1")
        if host.name == "bs1_11_1":
            host.setMAC("0:0:0:0:0:08")
        if host.name == "cs1_11_1":
            host.setMAC("0:0:0:0:0:06")
        if host.name == "ps1_11_1":
            host.setMAC("0:0:0:0:0:09")
        if host.name == "ds1_11_1":
            host.setMAC("0:0:0:0:0:0a")
        if host.name == "er1_11er1_12":
            host.setMAC("0:0:0:0:10:1", "er1_11er1_12-0")
        host.cmd("arp -s %s 1:2:3:4:5:6" % HSR_EGRESS_IP)
        host.cmd("arp -s %s 1:2:3:4:5:7" % HSR_LOCAL_IP)

    for host in net.hosts:
        host.cmd('ip route add 169.254.0.0/16 dev %s-0' % host.name)

    # sasaki
    # count=1
    for switch in net.switches:
        # switch.setMac("0:0:0:0:1:%x"%count)
        # count += 1
        if switch.name == "s2":
            Intf('eth10', node=switch)
        if switch.name == "s0":
            Intf('eth11', node=switch)

    net.start()
    os.system('ip link add name mininet type dummy')
    os.system('ip addr add 169.254.0.1/16 dev mininet')
    os.system('ip addr add 169.254.0.2/16 dev mininet')
    os.system('ip addr add 169.254.0.3/16 dev mininet')

    for switch in net.switches:
        for k, v in topo.switch_map.items():
            if v == switch.name:
                os.system('ip route add %s dev %s src 169.254.0.1'
                          % (k, switch.name))
                print('ip route add %s dev %s src 169.254.0.1'
                      % (k, switch.name))
    for host in net.hosts:
        elem_name = host.name.replace("_", "-")
        print("Starting supervisord on %s" % elem_name)
        host.cmd("%s -c gen/mininet/%s.conf" % (supervisord, elem_name))

        os.system('sudo ifconfig s3 hw ether 0:0:0:0:1:03')  # HSR MAC address
    os.system("arp -s %s 1:2:3:4:5:6" % HSR_LOCAL_IP)  # HSR MAC address

    CLI(net)
    net.stop()
    os.system('ip link delete mininet')

if __name__ == '__main__':
    main()
