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
# External packages
import yaml
# SCION
from lib.defines import DOCKER_COMPOSE_CONFIG_VERSION
from lib.util import (
    write_file,
)
from topology.common import (
    ArgsTopoDicts,
    docker_image,
    DOCKER_USR_VOL,
    sciond_svc_name
)
from topology.docker_utils import DockerUtilsGenArgs, DockerUtilsGenerator
from topology.sig import SIGGenArgs, SIGGenerator

DOCKER_CONF = 'scion-dc.yml'


class DockerGenArgs(ArgsTopoDicts):
    def __init__(self, args, topo_dicts, networks, port_gen=None):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict topo_dicts: The generated topo dicts from TopoGenerator.
        :param dict networks: The generated networks from SubnetGenerator.
        :param PortGenerator port_gen: The port generator
        """
        super().__init__(args, topo_dicts, port_gen)
        self.networks = networks


class DockerGenerator(object):
    def __init__(self, args):
        """
        :param DockerGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args
        self.dc_conf = {'version': DOCKER_COMPOSE_CONFIG_VERSION,
                        'services': {}, 'networks': {}, 'volumes': {}}
        self.elem_networks = {}
        self.bridges = {}
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())
        self.user_spec = os.environ.get('SCION_USERSPEC', '$LOGNAME')
        self.prefix = 'scion_docker_' if self.args.in_docker else 'scion_'

    def generate(self):
        self._create_networks()
        for topo_id, topo in self.args.topo_dicts.items():
            base = os.path.join(self.output_base, topo_id.base_dir(self.args.output_dir))
            self._gen_topo(topo_id, topo, base)
        if self.args.sig:
            self._gen_sig()
        docker_utils_gen = DockerUtilsGenerator(self._docker_utils_args())
        self.dc_conf = docker_utils_gen.generate()

        write_file(os.path.join(self.args.output_dir, DOCKER_CONF),
                   yaml.dump(self.dc_conf, default_flow_style=False))

    def _docker_utils_args(self):
        return DockerUtilsGenArgs(self.args, self.dc_conf, self.bridges, self.elem_networks)

    def _sig_args(self):
        return SIGGenArgs(self.args,  self.dc_conf, self.bridges, self.elem_networks)

    def _gen_topo(self, topo_id, topo, base):
        self._dispatcher_conf(topo_id, topo, base)
        self._br_conf(topo_id, topo, base)
        self._cs_conf(topo_id, topo, base)
        self._bs_conf(topo_id, topo, base)
        self._ps_conf(topo_id, topo, base)
        self._sciond_conf(topo_id, base)
        self._vol_conf(topo_id, topo)

    def _gen_sig(self):
        sig_gen = SIGGenerator(self._sig_args())
        self.dc_conf = sig_gen.generate()

    def _vol_conf(self, topo_id, topo):
        self.dc_conf['volumes']['vol_%sdisp_%s' % (self.prefix, topo_id.file_fmt())] = None
        for k, _ in topo.get("BorderRouters", {}).items():
            disp_id = '%s%s' % (topo_id.file_fmt(), k[-2:])
            self.dc_conf['volumes']['vol_%sdisp_br_%s' % (self.prefix, disp_id)] = None
        self.dc_conf['volumes']['vol_%ssciond_%s' % (self.prefix, topo_id.file_fmt())] = None

    def _create_networks(self):
        for network in self.args.networks:
            for elem in self.args.networks[network]:
                if elem not in self.elem_networks:
                    self.elem_networks[elem] = []
                ipv = 'ipv4'
                if self.args.networks[network][elem].ip.version == 6:
                    ipv = 'ipv6'
                self.elem_networks[elem].append({
                    'net': str(network),
                    ipv: self.args.networks[network][elem].ip
                })
            # Create docker networks
            prefix = 'scnd_' if self.args.in_docker else 'scn_'
            net_name = "%s%03d" % (prefix, len(self.bridges))
            self.bridges[str(network)] = net_name
            self.dc_conf['networks'][net_name] = {
                'ipam': {
                    'config': [{'subnet': str(network)}]
                },
                'driver': 'bridge',
                'driver_opts': {
                    'com.docker.network.bridge.name': net_name
                }
            }
            if network.version == 6:
                self.dc_conf['networks'][net_name]['enable_ipv6'] = True

    def _br_conf(self, topo_id, topo, base):
        for k, _ in topo.get("BorderRouters", {}).items():
            disp_id = '%s%s' % (topo_id.file_fmt(), k[-2:])
            entry = {
                'image': docker_image(self.args, 'border'),
                'container_name': self.prefix + k,
                'depends_on': [
                    'scion_disp_br_%s' % disp_id,
                ],
                'environment': {
                    'SU_EXEC_USERSPEC': self.user_spec,
                },
                'networks': {},
                'volumes': [
                    *DOCKER_USR_VOL,
                    self._disp_br_vol(disp_id),
                    self._logs_vol(),
                    '%s:/share/conf:ro' % os.path.join(base, k)
                ],
                'command': []
            }

            # Set BR IPs
            in_net = self.elem_networks[k + "_internal"][0]
            ipv = 'ipv4'
            if ipv not in in_net:
                ipv = 'ipv6'
            entry['networks'][self.bridges[in_net['net']]] = {
                '%s_address' % ipv: str(in_net[ipv])
            }
            for net in self.elem_networks[k]:
                ipv = 'ipv4'
                if ipv not in net:
                    ipv = 'ipv6'
                entry['networks'][self.bridges[net['net']]] = {
                    '%s_address' % ipv: str(net[ipv])
                }
            self.dc_conf['services']['scion_%s' % k] = entry

    def _cs_conf(self, topo_id, topo, base):
        raw_entry = {
            'image': docker_image(self.args, 'cert'),
            'depends_on': [
                sciond_svc_name(topo_id),
                'scion_disp_%s' % topo_id.file_fmt(),
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'network_mode': 'service:scion_disp_%s' % topo_id.file_fmt(),
            'volumes': self._std_vol(topo_id),
            'command': []
        }
        for k, v in topo.get("CertificateService", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = self.prefix + k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            self.dc_conf['services']['scion_%s' % k] = entry

    def _bs_conf(self, topo_id, topo, base):
        raw_entry = {
            'image': docker_image(self.args, 'beacon'),
            'depends_on': [
                sciond_svc_name(topo_id),
                'scion_disp_%s' % topo_id.file_fmt(),
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'network_mode': 'service:scion_disp_%s' % topo_id.file_fmt(),
            'volumes': self._std_vol(topo_id),
            'command': []
        }
        for k, v in topo.get("BeaconService", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = self.prefix + k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            self.dc_conf['services']['scion_%s' % k] = entry

    def _ps_conf(self, topo_id, topo, base):
        raw_entry = {
            'image': docker_image(self.args, 'path'),
            'depends_on': [
                sciond_svc_name(topo_id),
                'scion_disp_%s' % topo_id.file_fmt(),
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'network_mode': 'service:scion_disp_%s' % topo_id.file_fmt(),
            'volumes': self._std_vol(topo_id),
            'command': [],
        }
        for k, v in topo.get("PathService", {}).items():
            entry = copy.deepcopy(raw_entry)
            name = self.prefix + k
            entry['container_name'] = name
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            self.dc_conf['services']['scion_%s' % k] = entry

    def _dispatcher_conf(self, topo_id, topo, base):
        image = 'dispatcher_go'
        entry = {
            'image': docker_image(self.args, image),
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'networks': {},
            'volumes': [
                *DOCKER_USR_VOL,
                self._logs_vol()
            ]
        }
        self._br_dispatcher(copy.deepcopy(entry), topo_id, topo, base)
        self._infra_dispatcher(copy.deepcopy(entry), topo_id, base)

    def _br_dispatcher(self, prep_entry, topo_id, topo, base):
        # Create dispatcher for BR Ctrl Port
        for k in topo.get("BorderRouters", {}):
            entry = copy.deepcopy(prep_entry)
            ctrl_net = self.elem_networks[k + "_ctrl"][0]
            ipv = 'ipv4'
            if ipv not in ctrl_net:
                ipv = 'ipv6'
            ctrl_ip = str(ctrl_net[ipv])
            disp_id = '%s%s' % (topo_id.file_fmt(), k[-2:])
            entry['networks'][self.bridges[ctrl_net['net']]] = {'%s_address' % ipv: ctrl_ip}
            entry['container_name'] = '%sdisp_br_%s' % (self.prefix, disp_id)
            entry['volumes'].append(self._disp_br_vol(disp_id))
            conf = '%s:/share/conf:rw' % os.path.join(base, 'disp_br_%s' % disp_id)
            entry['volumes'].append(conf)
            self.dc_conf['services']['scion_disp_br_%s' % disp_id] = entry

    def _infra_dispatcher(self, entry, topo_id, base):
        # Create dispatcher for Infra
        net = self.elem_networks["disp" + topo_id.file_fmt()][0]
        ipv = 'ipv4'
        if ipv not in net:
            ipv = 'ipv6'
        ip = str(net[ipv])
        entry['networks'][self.bridges[net['net']]] = {'%s_address' % ipv: ip}
        entry['container_name'] = '%sdisp_%s' % (self.prefix, topo_id.file_fmt())
        entry['volumes'].append(self._disp_vol(topo_id))
        conf = '%s:/share/conf:rw' % os.path.join(base, 'disp_%s' % topo_id.file_fmt())
        entry['volumes'].append(conf)
        self.dc_conf['services']['scion_disp_%s' % topo_id.file_fmt()] = entry

    def _sciond_conf(self, topo_id, base):
        name = sciond_svc_name(topo_id)
        net = self.elem_networks["sd" + topo_id.file_fmt()][0]
        ipv = 'ipv4'
        if ipv not in net:
            ipv = 'ipv6'
        ip = str(net[ipv])
        entry = {
            'image': docker_image(self.args, 'sciond'),
            'container_name': '%ssd%s' % (self.prefix, topo_id.file_fmt()),
            'depends_on': [
                'scion_disp_%s' % topo_id.file_fmt()
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'volumes': [
                *self._std_vol(topo_id),
                '%s:/share/conf:ro' % os.path.join(base, 'endhost'),
            ],
            'networks': {
                self.bridges[net['net']]: {'%s_address' % ipv: ip}
            }
        }
        self.dc_conf['services'][name] = entry

    def _disp_br_vol(self, disp_id):
        return 'vol_%sdisp_br_%s:/run/shm/dispatcher:rw' % (self.prefix, disp_id)

    def _disp_vol(self, topo_id):
        return 'vol_%sdisp_%s:/run/shm/dispatcher:rw' % (self.prefix, topo_id.file_fmt())

    def _sciond_vol(self, topo_id):
        return 'vol_%ssciond_%s:/run/shm/sciond:rw' % (self.prefix, topo_id.file_fmt())

    def _logs_vol(self):
        return self.output_base + '/logs:/share/logs:rw'

    def _cache_vol(self):
        return self.output_base + '/gen-cache:/share/cache:rw'

    def _certs_vol(self):
        return self.output_base + '/gen-certs:/share/crypto:rw'

    def _std_vol(self, topo_id):
        return [
            *DOCKER_USR_VOL,
            self._disp_vol(topo_id),
            self._sciond_vol(topo_id),
            self._cache_vol(),
            self._logs_vol(),
            self._certs_vol(),
        ]
