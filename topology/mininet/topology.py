#!/usr/bin/python2

# Stdlib
import argparse
import os
import sys

# External
import configparser
import ipaddress
from mininet.cli import CLI
from mininet.log import lg
from mininet.link import Intf, Link, TCIntf
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

MAX_INTF_LEN = 15
NETWORKS_CONF = "gen/networks.conf"
LINKS_CONF = "topology/mininet/links.conf"
HSR_ADDR_FILE = "gen/hsr/hsr_addr.txt"


class ScionTopo(Topo):
    """
    Topology built from a SCION network config."
    """
    def __init__(self, mnconfig, hsr=False, **params):

        # Initialize topology
        Topo.__init__(self, **params)
        self.switch_map = {}
        self.hsr = hsr
        self._genTopo(mnconfig)

    def _genTopo(self, mnconfig):
        links = configparser.ConfigParser(interpolation=None)
        links.read(LINKS_CONF)

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
                    host_map[elem] = self.addHost(elem_name, ip=None)
                intf = ipaddress.ip_interface(intf_str)
                is_link = False
                if intf.network.prefixlen == intf.max_prefixlen - 1:
                    is_link = True
                intfName = "%s-%d" % (elem_name, is_link)
                assert len(intfName) <= MAX_INTF_LEN
                params = {'ip': str(intf)}
                if intfName in links.sections():
                    params.update(self._tcParamParser(links[intfName]))
                self.addLink(
                    host_map[elem], self.switch_map[name],
                    params,
                    intfName=intfName,
                )

    def _tcParamParser(self, section):
        """
        Returns properly formatted TCIntf config parameters
        """
        tcItems = {}
        if "jitter" in section:
            tcItems["jitter"] = section.get("jitter")
        if "delay" in section:
            tcItems["delay"] = section.get("delay")
        if "enable_ecn" in section:
            tcItems["enable_ecn"] = section.getboolean("enable_ecn")
        if "enable_red" in section:
            tcItems["enable_red"] = section.getboolean("enable_red")
        if "use_hfsc" in section:
            tcItems["use_hfsc"] = section.getboolean("use_hfsc")
        if "use_tbf" in section:
            tcItems["use_tbf"] = section.getboolean("use_tbf")
        if "bw" in section:
            tcItems["bw"] = section.getfloat("bw")
        if "loss" in section:
            tcItems["loss"] = section.getint("loss")
        return tcItems

    def addLink(self, node1, node2, params=None, intfName=None):
        if self.hsr:
            if node1 == "er1_13er1_11" or node2 == "er1_13er1_11":
                return
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


class ScionTCLink(Link):
    # mininet.link.TCLink mangles parameters, so reimplement it more cleanly and
    # correctly.
    def __init__(self, *args, **kwargs):
        kwargs["intf"] = TCIntf
        Link.__init__(self, *args, **kwargs)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r', '--hsr', action='store_true', help='Use HSR')
    args = parser.parse_args()

    lg.setLogLevel('info')
    supervisord = os.getenv("SUPERVISORD")
    assert supervisord

    mnconfig = configparser.ConfigParser(interpolation=None)
    mnconfig.read_file(open(NETWORKS_CONF), source=NETWORKS_CONF)
    topo = ScionTopo(mnconfig, args.hsr)
    net = Mininet(topo=topo, controller=RemoteController, link=ScionTCLink)

    if args.hsr:
        with open(HSR_ADDR_FILE) as f:
            hsr_internal_ip = f.readline()[:-1]
            hsr_external_ip = f.readline()
        for host in net.hosts:
            # static ARP setting to send packets to HSR
            if host.name == "er1_11er1_13":
                host.setMAC("0:0:0:0:0:CC", "er1_11er1_13-1")
            if host.name == "bs1_13_1":
                host.setMAC("0:0:0:0:0:08")
            if host.name == "cs1_13_1":
                host.setMAC("0:0:0:0:0:06")
            if host.name == "ps1_13_1":
                host.setMAC("0:0:0:0:0:09")
            if host.name == "ds1_13_1":
                host.setMAC("0:0:0:0:0:0a")
            host.cmd("arp -s %s 1:2:3:4:5:6" % hsr_external_ip)
            host.cmd("arp -s %s 1:2:3:4:5:7" % hsr_internal_ip)
        # TODO: Find switch assignment dynamically?
        for switch in net.switches:
            if switch.name == "s2":
                Intf("eth10", node=switch)
            if switch.name == "s4":
                Intf("eth11", node=switch)

    for host in net.hosts:
        host.cmd('ip route add 169.254.0.0/16 dev %s-0' % host.name)

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
    for host in net.hosts:
        elem_name = host.name.replace("_", "-")
        print("Starting supervisord on %s" % elem_name)
        host.cmd("%s -c gen/mininet/%s.conf" % (supervisord, elem_name))

    if args.hsr:
        os.system('sudo ifconfig s4 hw ether 0:0:0:0:1:03')  # HSR MAC address
        os.system("arp -s %s 1:2:3:4:5:6" % hsr_internal_ip)  # HSR MAC address

    CLI(net)
    net.stop()
    os.system('ip link delete mininet')

if __name__ == '__main__':
    main()
