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
import copy
import os
from typing import Mapping
# External packages
import yaml
# SCION
from topology.defines import DOCKER_COMPOSE_CONFIG_VERSION
from topology.util import write_file
from topology.common import (
    ArgsTopoDicts,
    docker_host,
    docker_image,
    sciond_name,
)
from topology.docker_utils import DockerUtilsGenArgs, DockerUtilsGenerator
from topology.net import NetworkDescription, IPNetwork
from topology.sig import SIGGenArgs, SIGGenerator

DOCKER_CONF = 'scion-dc.yml'


class DockerGenArgs(ArgsTopoDicts):
    def __init__(self, args, topo_dicts,
                 networks: Mapping[IPNetwork, NetworkDescription]):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict topo_dicts: The generated topo dicts from TopoGenerator.
        :param dict networks: The generated networks from SubnetGenerator.
        """
        super().__init__(args, topo_dicts)
        self.networks = networks


class DockerGenerator(object):
    def __init__(self, args):
        """
        :param DockerGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args
        self.dc_conf = {
            'version': DOCKER_COMPOSE_CONFIG_VERSION,
            'name': 'scion',
            'services': {},
            'networks': {},
            'volumes': {}
        }
        self.elem_networks = {}
        self.bridges = {}
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())
        self.user = '%d:%d' % (os.getuid(), os.getgid())

    def generate(self):
        self._create_networks()
        for topo_id, topo in self.args.topo_dicts.items():
            base = os.path.join(self.output_base,
                                topo_id.base_dir(self.args.output_dir))
            self._gen_topo(topo_id, topo, base)
        if self.args.sig:
            self._gen_sig()
        docker_utils_gen = DockerUtilsGenerator(self._docker_utils_args())
        self.dc_conf = docker_utils_gen.generate()

        write_file(os.path.join(self.args.output_dir, DOCKER_CONF),
                   yaml.dump(self.dc_conf, default_flow_style=False))

    def _docker_utils_args(self):
        return DockerUtilsGenArgs(self.args, self.dc_conf, self.bridges,
                                  self.elem_networks)

    def _sig_args(self):
        return SIGGenArgs(self.args, self.dc_conf, self.bridges,
                          self.elem_networks)

    def _gen_topo(self, topo_id, topo, base):
        self._dispatcher_conf(topo_id, topo, base)
        self._br_conf(topo_id, topo, base)
        self._control_service_conf(topo_id, topo, base)
        self._sciond_conf(topo_id, base)

    def _gen_sig(self):
        sig_gen = SIGGenerator(self._sig_args())
        self.dc_conf = sig_gen.generate()

    def _create_networks(self):
        # first find v4 allocations, those networks don't need to be generated.
        v4nets = {}
        ignore_nets = []
        for network, net_desc in self.args.networks.items():
            if network.version == 6:
                continue
            if net_desc.name.endswith('_v4'):
                v4nets[net_desc.name[:-3]] = network
                ignore_nets.append(network)

        for network, net_desc in self.args.networks.items():
            if network in ignore_nets:
                continue
            for elem in net_desc.ip_net:
                if elem not in self.elem_networks:
                    self.elem_networks[elem] = []
                ipv = 'ipv4'
                ip = net_desc.ip_net[elem].ip
                if ip.version == 6:
                    ipv = 'ipv6'
                self.elem_networks[elem].append({'net': str(network), ipv: ip})
            # Create docker networks
            prefix = 'scn_'
            net_name = "%s%03d" % (prefix, len(self.bridges))
            self.bridges[str(network)] = net_name
            self.dc_conf['networks'][net_name] = {
                'ipam': {
                    'config': [{
                        'subnet': str(network)
                    }]
                },
                'driver': 'bridge',
                'driver_opts': {
                    'com.docker.network.bridge.name': net_name
                }
            }
            if net_desc.name in v4nets:
                v4_net = v4nets[net_desc.name]
                self.dc_conf['networks'][net_name]['ipam']['config'].append(
                    {'subnet': str(v4_net)})
            if network.version == 6:
                self.dc_conf['networks'][net_name]['enable_ipv6'] = True

    def _br_conf(self, topo_id, topo, base):
        for k, _ in topo.get("border_routers", {}).items():
            image = docker_image(self.args, 'router')
            entry = {
                'image': image,
                'networks': {},
                'user': self.user,
                'volumes': ['%s:/etc/scion:ro' % base],
                'command': ['--config', '/etc/scion/%s.toml' % k]
            }
            # add data networks:
            net_keys = [k, k + '_internal']
            for net_key in net_keys:
                for net in self.elem_networks[net_key]:
                    ipv = 'ipv4'
                    if ipv not in net:
                        ipv = 'ipv6'
                    entry['networks'][self.bridges[net['net']]] = {
                        '%s_address' % ipv: str(net[ipv])
                    }
            self.dc_conf['services'][k] = entry

    def _control_service_conf(self, topo_id, topo, base):
        for k in topo.get("control_service", {}).keys():
            entry = {
                'image':
                docker_image(self.args, 'control'),
                'depends_on': ['disp_%s' % k],
                'network_mode':
                'service:disp_%s' % k,
                'user':
                self.user,
                'volumes': [
                    self._cache_vol(),
                    '%s:/etc/scion:ro' % base,
                ],
                'command': ['--config', '/etc/scion/%s.toml' % k]
            }
            self.dc_conf['services'][k] = entry

    def _dispatcher_conf(self, topo_id, topo, base):
        image = 'dispatcher'
        base_entry = {
            'extra_hosts': ['jaeger:%s' % docker_host(self.args.docker)],
            'image': docker_image(self.args, image),
            'networks': {},
            'user': self.user,
            'volumes': [],
        }
        keys = list(topo.get("control_service", {}))
        if topo.get("test_dispatcher"):
            keys.append("tester_%s" % topo_id.file_fmt())
        for disp_id in keys:
            entry = copy.deepcopy(base_entry)
            net_key = disp_id
            net = self.elem_networks[net_key][0]
            ipv = 'ipv4'
            if ipv not in net:
                ipv = 'ipv6'
            ip = str(net[ipv])
            entry['networks'][self.bridges[net['net']]] = {
                '%s_address' % ipv: ip
            }
            conf = '%s:/etc/scion:rw' % base
            entry['volumes'].append(conf)
            entry['command'] = [
                '--config', '/etc/scion/disp_%s.toml' % disp_id
            ]

            self.dc_conf['services']['disp_%s' % disp_id] = entry

    def _sciond_conf(self, topo_id, base):
        name = sciond_name(topo_id)
        net = self.elem_networks["sd" + topo_id.file_fmt()][0]
        ipv = 'ipv4'
        if ipv not in net:
            ipv = 'ipv6'
        ip = str(net[ipv])
        disp_id = 'cs%s-1' % topo_id.file_fmt()
        entry = {
            'extra_hosts': ['jaeger:%s' % docker_host(self.args.docker)],
            'image':
            docker_image(self.args, 'daemon'),
            'depends_on': ['disp_%s' % disp_id],
            'user':
            self.user,
            'volumes': [
                self._cache_vol(),
                '%s:/etc/scion:ro' % base
            ],
            'networks': {
                self.bridges[net['net']]: {
                    '%s_address' % ipv: ip
                }
            },
            'command': ['--config', '/etc/scion/sd.toml'],
        }
        self.dc_conf['services'][name] = entry

    def _cache_vol(self):
        return self.output_base + '/gen-cache:/share/cache:rw'
