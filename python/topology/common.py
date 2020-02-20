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
import subprocess
import sys

# SCION
from lib.scion_addr import ISD_AS
from topology.net import AddressProxy

COMMON_DIR = 'endhost'

SCION_SERVICE_NAMES = (
    "ControlService",
    "BorderRouters",
    "ColibriService",
)

BR_CONFIG_NAME = 'br.toml'
BS_CONFIG_NAME = 'bs.toml'
CS_CONFIG_NAME = 'cs.toml'
PS_CONFIG_NAME = 'ps.toml'
CO_CONFIG_NAME = 'co.toml'
SD_CONFIG_NAME = 'sd.toml'
DISP_CONFIG_NAME = 'disp.toml'
SIG_CONFIG_NAME = 'sig.toml'

DOCKER_USR_VOL = ['/etc/passwd:/etc/passwd:ro', '/etc/group:/etc/group:ro']

SD_API_PORT = 30255


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
    def __init__(self, args, topo_dicts):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict topo_dicts: The generated topo dicts from TopoGenerator.
        """
        super().__init__(args)
        self.topo_dicts = topo_dicts


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


def prom_addr_br(br_id, br_ele, port):
    """Get the prometheus address for a border router"""
    pub = get_pub(br_ele['InternalAddrs'])
    return "[%s]:%s" % (pub['PublicOverlay']['Addr'].ip, port)


def prom_addr_infra(docker, infra_id, infra_ele, port):
    """Get the prometheus address for an infrastructure element."""
    pub = get_pub(infra_ele['Addrs'])
    return "[%s]:%s" % (pub['Public']['Addr'].ip, port)


def sciond_ip(docker, topo_id, networks):
    for i, net in enumerate(networks):
        for prog, ip_net in networks[net].items():
            if prog == 'sd%s' % topo_id.file_fmt():
                return ip_net.ip
    return None


def prom_addr_dispatcher(docker, topo_id, networks, port, name):
    if not docker:
        return "[127.0.0.1]:%s" % port
    target_name = ''
    if name.startswith('disp_br'):
        target_name = 'br%s%s_ctrl' % (topo_id.file_fmt(), name[-2:])
    elif name.startswith('disp_sig'):
        target_name = 'sig%s' % topo_id.file_fmt()
    else:
        target_name = 'disp%s' % topo_id.file_fmt()
    for _, net in enumerate(networks):
        if target_name in networks[net]:
            return '[%s]:%s' % (networks[net][target_name].ip, port)
    return None


def get_pub(topo_addr):
    pub = topo_addr.get('IPv6')
    if pub is not None:
        return pub
    return topo_addr['IPv4']


def get_pub_ip(topo_addr):
    return get_pub(topo_addr)["Public"]["Addr"].ip


def get_l4_port(topo_addr):
    return get_pub(topo_addr)["Public"]["L4Port"]


def srv_iter(topo_dicts, out_dir, common=False):
    for topo_id, as_topo in topo_dicts.items():
        base = topo_id.base_dir(out_dir)
        for service in SCION_SERVICE_NAMES:
            for elem in as_topo[service]:
                yield topo_id, as_topo, os.path.join(base, elem)
        if common:
            yield topo_id, as_topo, os.path.join(base, COMMON_DIR)


def docker_image(args, image):
    if args.docker_registry:
        image = '%s/%s' % (args.docker_registry, image)
    else:
        image = 'scion_%s' % image
    if args.image_tag:
        image = '%s:%s' % (image, args.image_tag)
    return image


def docker_host(in_docker, docker, addr=None):
    if in_docker:
        # If in-docker we need to know the DOCKER0 IP
        addr = os.getenv('DOCKER0', None)
        if not addr:
            print('DOCKER0 env variable required! Exiting!')
            sys.exit(1)
    elif docker or not addr:
        # Using docker topology or there is no default addr,
        # we directly get the DOCKER0 IP
        addr = docker_ip()
    return addr


def docker_ip():
    return subprocess.check_output(['tools/docker-ip']).decode("utf-8").strip()


def remote_nets(networks, topo_id):
    """
    Returns the subnets of all remote ASes the SIG in topo_id is connected to.
    :param networks dict: Scion elem to subnet/IP map.
    :param topo_id: A key of a topo dict generated by TopoGenerator.
    :return: String of comma separated subnets.
    """
    rem_nets = []
    for key in networks:
        if 'sig' in key and topo_id.file_fmt() not in key:
            rem_nets.append(str(networks[key][0]['net']))
    return ','.join(rem_nets)


def sciond_name(topo_id):
    return 'sd%s' % topo_id.file_fmt()


def sciond_svc_name(topo_id):
    return 'scion_%s' % sciond_name(topo_id)


def json_default(o):
    if isinstance(o, AddressProxy):
        return str(o.ip)
    raise TypeError
