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

# Stdlib
import os

# SCION
from lib.packet.scion_addr import ISD_AS

COMMON_DIR = 'endhost'

SCION_SERVICE_NAMES = (
    "BeaconService",
    "CertificateService",
    "BorderRouters",
    "PathService",
    "DiscoveryService",
)


class ArgsBase:
    def __init__(self, args):
        for k, v in vars(args).items():
            setattr(self, k, v)


class ArgsTopoConfig(ArgsBase):
    def __init__(self, args, topo_config):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict topo_config: The parsed topology config.
        """
        super().__init__(args)
        self.config = topo_config


class ArgsTopoDicts(ArgsBase):
    def __init__(self, args, topo_dicts, port_gen=None):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict topo_dicts: The generated topo dicts from TopoGenerator.
        :param PortGenerator port_gen: The port generator
        """
        super().__init__(args)
        self.topo_dicts = topo_dicts
        self.port_gen = port_gen


class TopoID(ISD_AS):
    def ISD(self):
        return "ISD%s" % self.isd_str()

    def AS(self):
        return "AS%s" % self.as_str()

    def AS_file(self):
        return "AS%s" % self.as_file_fmt()

    def file_fmt(self):
        return "%s-%s" % (self.isd_str(), self.as_file_fmt())

    def base_dir(self, out_dir):
        return os.path.join(out_dir, self.ISD(), self.AS_file())

    def __lt__(self, other):
        return str(self) < str(other)

    def __repr__(self):
        return "<TopoID: %s>" % self


def _prom_addr_br(br_id, br_ele, port_gen):
    """Get the prometheus address for a border router"""
    pub = _get_pub(br_ele['InternalAddrs'])
    return "[%s]:%s" % (pub['PublicOverlay']['Addr'].ip, port_gen.register(br_id + "prom"))


def _prom_addr_infra(infra_id, infra_ele, port_gen):
    """Get the prometheus address for an infrastructure element."""
    pub = _get_pub(infra_ele['Addrs'])
    return "[%s]:%s" % (pub['Public']['Addr'].ip, port_gen.register(infra_id + "prom"))


def _get_pub(topo_addr):
    pub = topo_addr.get('IPv6')
    if pub is not None:
        return pub
    return topo_addr['IPv4']


def _get_pub_ip(topo_addr):
    return _get_pub(topo_addr)["Public"]["Addr"].ip


def _get_l4_port(topo_addr):
    return _get_pub(topo_addr)["Public"]["L4Port"]


def _srv_iter(topo_dicts, out_dir, common=False):
    for topo_id, as_topo in topo_dicts.items():
        base = topo_id.base_dir(out_dir)
        for service in SCION_SERVICE_NAMES:
            for elem in as_topo[service]:
                yield topo_id, as_topo, os.path.join(base, elem)
        if common:
            yield topo_id, as_topo, os.path.join(base, COMMON_DIR)
