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
from string import Template
# External packages
import yaml
# SCION
from lib.app.sciond import get_default_sciond_path
from lib.defines import SCIOND_API_SOCKDIR
from lib.packet.scion_addr import ISD_AS
from lib.util import (
    read_file,
    write_file,
)
from topology.common import (
    ArgsTopoDicts,
    docker_image,
    DOCKER_USR_VOL,
    prom_addr_infra,
    sciond_name,
    sciond_svc_name
)
from topology.docker_utils import DockerUtilsGenArgs, DockerUtilsGenerator
from topology.prometheus import (
    BS_PROM_PORT,
    CS_PROM_PORT,
    PS_PROM_PORT
)
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
        self.dc_conf = {'version': '3', 'services': {}, 'networks': {}, 'volumes': {}}
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
        self._vol_conf(topo_id)

    def _gen_sig(self):
        sig_gen = SIGGenerator(self._sig_args())
        self.dc_conf = sig_gen.generate()

    def _vol_conf(self, topo_id):
        self.dc_conf['volumes']['vol_%sdisp_%s' % (self.prefix, topo_id.file_fmt())] = None
        self.dc_conf['volumes']['vol_%sdisp_br_%s' % (self.prefix, topo_id.file_fmt())] = None
        self.dc_conf['volumes']['vol_%ssciond_%s' % (self.prefix, topo_id.file_fmt())] = None

    def _create_networks(self):
        for network in self.args.networks:
            for elem in self.args.networks[network]:
                if elem not in self.elem_networks:
                    self.elem_networks[elem] = []
                self.elem_networks[elem].append(
                    {'net': str(network), 'ipv4': self.args.networks[network][elem].ip})
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

    def _br_conf(self, topo_id, topo, base):
        raw_entry = {
            'image': docker_image(self.args, 'border'),
            'depends_on': [
                'scion_disp_br_%s' % topo_id.file_fmt(),
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'networks': {},
            'volumes': [
                *DOCKER_USR_VOL,
                'vol_%sdisp_br_%s:/run/shm/dispatcher:rw' % (self.prefix, topo_id.file_fmt()),
                self._logs_vol()
            ],
            'command': []
        }
        for k, v in topo.get("BorderRouters", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = self.prefix + k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            # Set BR IPs
            in_net = self.elem_networks[k + "_internal"][0]
            entry['networks'][self.bridges[in_net['net']]] = {'ipv4_address': str(in_net['ipv4'])}
            for net in self.elem_networks[k]:
                entry['networks'][self.bridges[net['net']]] = {'ipv4_address': str(net['ipv4'])}
            self.dc_conf['services']['scion_%s' % k] = entry

    def _cs_conf(self, topo_id, topo, base):
        image = 'cert_py' if self.args.cert_server == 'py' else 'cert'
        raw_entry = {
            'image': docker_image(self.args, image),
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
            if self.args.cert_server == 'py':
                sciond = get_default_sciond_path(ISD_AS(topo["ISD_AS"]))
                entry['command'].append('--spki_cache_dir=cache')
                prom_addr = prom_addr_infra(self.args.docker, k, v, CS_PROM_PORT)
                entry['command'].append('--prom=%s' % prom_addr)
                entry['command'].append('--sciond_path=%s' % sciond)
                entry['command'].append(k)
                entry['command'].append('conf')
            self.dc_conf['services']['scion_%s' % k] = entry

    def _bs_conf(self, topo_id, topo, base):
        raw_entry = {
            'image': docker_image(self.args, 'beacon_py'),
            'depends_on': [
                sciond_svc_name(topo_id),
                'scion_disp_%s' % topo_id.file_fmt(),
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'network_mode': 'service:scion_disp_%s' % topo_id.file_fmt(),
            'volumes': self._std_vol(topo_id),
            'command': [
                '--spki_cache_dir=cache'
            ]
        }
        for k, v in topo.get("BeaconService", {}).items():
            entry = copy.deepcopy(raw_entry)
            name = self.prefix + k
            entry['container_name'] = name
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            prom_addr = prom_addr_infra(self.args.docker, k, v, BS_PROM_PORT)
            entry['command'].append('--prom=%s' % prom_addr)
            entry['command'].append('--sciond_path=%s' %
                                    get_default_sciond_path(ISD_AS(topo["ISD_AS"])))
            entry['command'].append(k)
            entry['command'].append('conf')
            self.dc_conf['services']['scion_%s' % k] = entry

    def _ps_conf(self, topo_id, topo, base):
        image = 'path_py' if self.args.path_server == 'py' else 'path'
        raw_entry = {
            'image': docker_image(self.args, image),
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
            if self.args.path_server == 'py':
                entry['command'].append('--spki_cache_dir=cache')
                prom_addr = prom_addr_infra(self.args.docker, k, v, PS_PROM_PORT)
                entry['command'].append('--prom=%s' % prom_addr)
                entry['command'].append('--sciond_path=%s' %
                                        get_default_sciond_path(ISD_AS(topo["ISD_AS"])))
                entry['command'].append(k)
                entry['command'].append('conf')
            self.dc_conf['services']['scion_%s' % k] = entry

    def _dispatcher_conf(self, topo_id, topo, base):
        image = 'dispatcher_go' if self.args.dispatcher == 'go' else 'dispatcher'
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

    def _br_dispatcher(self, entry, topo_id, topo, base):
        # Create dispatcher for BR Ctrl Port
        for k in topo.get("BorderRouters", {}):
            ctrl_net = self.elem_networks[k + "_ctrl"][0]
            ctrl_ip = str(ctrl_net['ipv4'])
            entry['networks'][self.bridges[ctrl_net['net']]] = {'ipv4_address': ctrl_ip}
        entry['container_name'] = '%sdisp_br_%s' % (self.prefix, topo_id.file_fmt())
        vol = 'vol_%sdisp_br_%s:/run/shm/dispatcher:rw' % (self.prefix, topo_id.file_fmt())
        entry['volumes'].append(vol)
        conf = '%s:/share/conf:rw' % os.path.join(base, 'disp_br_%s' % topo_id.file_fmt())
        entry['volumes'].append(conf)
        self.dc_conf['services']['scion_disp_br_%s' % topo_id.file_fmt()] = entry
        # Dispatcher config
        if not self.args.dispatcher == 'go':
            self._generate_disp_cfg("disp_br_%s" % topo_id.file_fmt(), topo_id)

    def _infra_dispatcher(self, entry, topo_id, base):
        # Create dispatcher for Infra
        net = self.elem_networks["disp" + topo_id.file_fmt()][0]
        ip = str(net['ipv4'])
        entry['networks'][self.bridges[net['net']]] = {'ipv4_address': ip}
        entry['container_name'] = '%sdisp_%s' % (self.prefix, topo_id.file_fmt())
        entry['volumes'].append(self._disp_vol(topo_id))
        conf = '%s:/share/conf:rw' % os.path.join(base, 'disp_%s' % topo_id.file_fmt())
        entry['volumes'].append(conf)
        self.dc_conf['services']['scion_disp_%s' % topo_id.file_fmt()] = entry
        # Dispatcher config
        if not self.args.dispatcher == 'go':
            self._generate_disp_cfg("disp_%s" % topo_id.file_fmt(), topo_id)

    def _sciond_conf(self, topo_id, base):
        name = sciond_svc_name(topo_id)
        image = 'sciond_py' if self.args.sciond == 'py' else 'sciond'
        net = self.elem_networks["sd" + topo_id.file_fmt()][0]
        ip = str(net['ipv4'])
        entry = {
            'image': docker_image(self.args, image),
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
                self.bridges[net['net']]: {'ipv4_address': ip}
            }
        }
        if self.args.sciond == 'py':
            entry['command'] = [
                '--api-addr=%s' % os.path.join(SCIOND_API_SOCKDIR, "%s.sock" % name),
                '--log_dir=logs',
                '--spki_cache_dir=cache',
                sciond_name(topo_id),
                'conf'
            ]
        self.dc_conf['services'][name] = entry

    def _generate_disp_cfg(self, elem, topo_id):
        elem_dir = os.path.join(topo_id.base_dir(self.args.output_dir), elem)
        cfg = "%s/dispatcher.zlog.conf" % elem_dir
        tmpl = Template(read_file("topology/zlog.tmpl"))
        write_file(cfg, tmpl.substitute(name="dispatcher", elem=elem))

    def _disp_vol(self, topo_id):
        return 'vol_%sdisp_%s:/run/shm/dispatcher:rw' % (self.prefix, topo_id.file_fmt())

    def _sciond_vol(self, topo_id):
        return 'vol_%ssciond_%s:/run/shm/sciond:rw' % (self.prefix, topo_id.file_fmt())

    def _logs_vol(self):
        return self.output_base + '/logs:/share/logs:rw'

    def _cache_vol(self):
        return self.output_base + '/gen-cache:/share/cache:rw'

    def _std_vol(self, topo_id):
        return [
            *DOCKER_USR_VOL,
            self._disp_vol(topo_id),
            self._sciond_vol(topo_id),
            self._cache_vol(),
            self._logs_vol()
        ]
