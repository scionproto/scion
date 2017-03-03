#!/usr/bin/python2

# Stdlib
import ipaddress
import os
import sys

# External
import configparser
from mininet.cli import CLI
from mininet.log import lg
# node needs to come before link to avoid circular dependency
from mininet.node import RemoteController
from mininet.link import Link, TCIntf
from mininet.net import Mininet
from mininet.topo import Topo

MAX_INTF_LEN = 15
NETWORKS_CONF = "gen/networks.conf"
LINKS_CONF = "topology/mininet/links.conf"


class ScionTopo(Topo):
    """
    Topology built from a SCION network config."
    """
    def __init__(self, mnconfig, **params):
        Topo.__init__(self, **params)
        self.switch_map = {}
        self._genTopo(mnconfig)

    def _genTopo(self, mnconfig):
        links = configparser.ConfigParser(interpolation=None)
        links.read(LINKS_CONF)

        for i, name in enumerate(mnconfig.sections()):
            self.switch_map[name] = self.addSwitch("s%s" % i)

        host_map = {}
        for name, section in mnconfig.items():
            for elem, addr in section.items():
                if ipaddress.ip_address(addr).is_loopback:
                    print("""ERROR: The IP address for %s (%s) is a loopback
                          address""" % (elem, addr))
                    print("Try running scion.sh topology -m")
                    sys.exit(1)
                network = ipaddress.ip_network(unicode(section.name))
                # The config is utf8, need to convert to a plain string to avoid
                # tickling bugs in mininet.
                elem = str(elem)
                elem_name = elem.replace("-", "_")
                if elem not in host_map:
                    host_map[elem] = self.addHost(elem_name, ip=None)
                intf = ipaddress.ip_interface(
                    "%s/%d" % (addr, network.prefixlen))
                is_link = False
                if intf.network.prefixlen == intf.max_prefixlen - 1:
                    is_link = True
                intfName = "%s-%d" % (elem_name, is_link)
                assert len(intfName) <= MAX_INTF_LEN, intfName
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
        port1, port2 = self.addPort(node1, node2, None, None)
        key = tuple(self.sorted([node1, node2]))
        # Map the supplied params to the node1 interface, even if sorting turns
        # it into the second interface.
        opts = {"port1": port1, "port2": port2, "params1": params,
                "intfName1": intfName, "node1": node1, "node2": node2}
        self.g.add_edge(node1, node2, key, opts)
        return key


class ScionTCLink(Link):
    # mininet.link.TCLink mangles parameters, so reimplement it more cleanly and
    # correctly.
    def __init__(self, *args, **kwargs):
        kwargs["intf"] = TCIntf
        Link.__init__(self, *args, **kwargs)


def main():
    lg.setLogLevel('info')
    supervisord = os.getenv("SUPERVISORD")
    assert supervisord
    topology = configparser.ConfigParser(interpolation=None)
    topology.read_file(open(NETWORKS_CONF), source=NETWORKS_CONF)
    topo = ScionTopo(topology)
    net = Mininet(topo=topo, controller=RemoteController, link=ScionTCLink)
    for host in net.hosts:
        host.cmd('export DISPATCHER_ID=%s' % host.name)
        host.cmd('ip route add 169.254.0.0/16 dev %s-0' % host.name)
    net.start()
    os.system('ip link add name mininet type dummy')
    os.system('ip addr add 169.254.0.1/16 dev mininet')
    os.system('ip addr add 169.254.0.2/16 dev mininet')
    os.system('ip addr add 169.254.0.3/16 dev mininet')

    for switch in net.switches:
        for k, v in topo.switch_map.items():
            if v == switch.name:
                os.system('ip link set dev %s up' % switch.name)
                os.system('ip route add %s dev %s src 169.254.0.1'
                          % (k, switch.name))
    for host in net.hosts:
        elem_name = host.name.replace("_", "-")
        print("Starting supervisord on %s" % elem_name)
        host.cmd("%s -c gen/mininet/%s.conf" % (supervisord, elem_name))
    CLI(net)
    net.stop()
    os.system('ip link delete mininet')

if __name__ == '__main__':
    main()
