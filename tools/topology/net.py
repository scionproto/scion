# Copyright 2014 ETH Zurich
# Copyright 2018 ETH Zurich, Anapaya Systems
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
"""
:mod:`net` --- SCION topology net generators
=============================================
"""
# Stdlib
import logging
import math
import sys
from collections import defaultdict
from ipaddress import (
    ip_interface,
    ip_network,
    IPv4Address,
    IPv6Address,
    IPv4Network,
    IPv6Network,
    IPv4Interface,
    IPv6Interface,
)
from typing import Mapping, Union

# External packages
import yaml

# SCION
from topology.defines import DEFAULT_NETWORK, DEFAULT_SCN_DC_NETWORK, DEFAULT6_NETWORK_ADDR

IPAddress = Union[IPv4Address, IPv6Address]
IPNetwork = Union[IPv4Network, IPv6Network]
IPInterface = Union[IPv4Interface, IPv6Interface]


class NetworkDescription(object):
    def __init__(self, name: str, ip_net: Mapping[str, IPInterface]):
        self.name = name
        self.ip_net = ip_net


class AddressProxy(yaml.YAMLObject):
    yaml_tag = ""

    def __init__(self):
        self._intf = None
        self.ip = None

    def set_intf(self, intf):
        self._intf = intf
        self.ip = self._intf.ip

    def __str__(self):
        return str(self._intf)

    @classmethod
    def to_yaml(cls, dumper, inst):
        return dumper.represent_scalar('tag:yaml.org,2002:str', str(inst.ip))


class AddressGenerator(object):
    def __init__(self, docker):
        self._addrs = defaultdict(lambda: AddressProxy())
        self.docker = docker

    def register(self, id_: str) -> AddressProxy:
        return self._addrs[id_]

    def alloc_addrs(self, subnet) -> Mapping[str, IPInterface]:
        hosts = subnet.hosts()
        interfaces = {}
        # With the docker backend, docker itself claims the first ip of every network
        if self.docker:
            next(hosts)
        for elem, proxy in sorted(self._addrs.items()):
            intf = ip_interface("%s/%s" % (next(hosts), subnet.prefixlen))
            interfaces[elem] = intf
            proxy.set_intf(intf)
        return interfaces

    def __len__(self):
        return len(self._addrs)


class SubnetGenerator(object):
    def __init__(self, network: str, docker: bool):
        self.docker = docker
        if self.docker and network == DEFAULT_NETWORK:
            network = DEFAULT_SCN_DC_NETWORK
        if "/" not in network:
            logging.critical("No prefix length specified for network '%s'",
                             network)
        try:
            self._net = ip_network(network)
        except ValueError:
            logging.critical("Invalid network '%s'", network)
            sys.exit(1)
        self._subnets = defaultdict(lambda: AddressGenerator(self.docker)) \
            # type: Mapping[str, AddressGenerator]
        self._allocations = defaultdict(list)
        # Initialise the allocations with the supplied network, making sure to
        # exclude 127.0.0.0/30 (for v4) and DEFAULT6_NETWORK_ADDR/126 (for v6)
        # if it's contained in the network.
        # - .0 is treated as a broadcast address by the kernel
        # - .1 is the normal loopback address
        # - .[23] are used for clients to bind to for testing purposes.
        if self._net.version == 4:
            exclude = ip_network("127.0.0.0/30")
        else:
            exclude = ip_network(DEFAULT6_NETWORK_ADDR + "/126")

        if self._net.overlaps(exclude):
            self._exclude_net(self._net, exclude)
            return

        self._allocations[self._net.prefixlen].append(self._net)

    def register(self, location: str) -> AddressGenerator:
        return self._subnets[location]

    def alloc_subnets(self) -> Mapping[IPNetwork, NetworkDescription]:
        max_prefix = self._net.max_prefixlen
        networks = {}
        for topo, subnet in sorted(self._subnets.items(), key=lambda x: str(x)):
            if not self.docker:
                # Figure out what size subnet we need. If it's a link, then we just
                # need a /31 (or /127), otherwise add 2 to the subnet size to cover
                # the network and broadcast addresses.
                if len(subnet) == 2:
                    req_prefix = max_prefix - 1
                else:
                    req_prefix = max_prefix - math.ceil(math.log2(len(subnet) + 2))
            else:
                # Docker needs space for a network and broadcast address as well as an IP linking
                # to the host
                req_prefix = max_prefix - math.ceil(math.log2(len(subnet) + 3))

            # Search all subnets from that size upwards
            for prefix in range(req_prefix, -1, -1):
                if not self._allocations[prefix]:
                    # No subnets available at this size
                    continue
                alloc = self._allocations[prefix].pop()
                # Carve out subnet of the required size
                new_net = next(alloc.subnets(new_prefix=req_prefix))
                new_net = _workaround_ip_network_hosts_py35(new_net)
                logging.debug("Allocating %s from %s for subnet size %d" %
                              (new_net, alloc, len(subnet)))
                networks[new_net] = NetworkDescription(topo, subnet.alloc_addrs(new_net))
                # Repopulate the allocations list with the left-over space
                self._exclude_net(alloc, new_net)
                break
            else:
                logging.critical("Unable to allocate /%d subnet" % req_prefix)
                sys.exit(1)
        return networks

    def _exclude_net(self, alloc, net):
        for net in alloc.address_exclude(net):
            self._allocations[net.prefixlen].append(net)


class PortGenerator(object):
    # XXX(JordiSubira): We keep this in the default range. If the configured range,
    # doesn't include the 31000-32767 range, the services will be able to operate
    # with the shim dispatcher.
    def __init__(self):
        self.iter = iter(range(31000, 32767))
        self._ports = defaultdict(lambda: next(self.iter))

    def register(self, id_: str) -> int:
        p = self._ports[id_]
        # reserve a quic port
        self._ports[id_+"quic"]
        return p


def socket_address_str(ip: IPAddress, port: int) -> str:
    if ip.version == 4:
        return "%s:%d" % (ip, port)
    return "[%s]:%d" % (ip, port)


def _workaround_ip_network_hosts_py35(net: IPNetwork) -> IPNetwork:
    """
    Returns an _identical_ ipaddress.ip_network for which hosts() which will work as it should.

    This works around a regression in python 3.5, where the behaviour of hosts was broken
    when using a certain form of the ip_network constructor.
    This regression is fixed in python 3.6.6 / 3.7.0.
    See https://bugs.python.org/issue27683
    """
    return ip_network('%s/%i' % (net.network_address, net.prefixlen))
