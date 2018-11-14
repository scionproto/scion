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
from shutil import copyfile
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
from topology.common import _prom_addr_br, _prom_addr_infra, ArgsTopoDicts
from topology.utils import TesterGenArgs, TesterGenerator, UtilsGenArgs, UtilsGenerator

DOCKER_NETWORK_CONF = 'networks-dc.yml'
DOCKER_VOLUME_CONF = 'volumes-dc.yml'
DOCKER_SCION_CONF = 'scion-dc.yml'


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
        self.dc_vol_conf = {'version': '3', 'volumes': {}}
        self.dc_net_conf = {'version': '3', 'networks': {}}
        self.dc_conf = {'version': '3', 'services': {}}
        self.elem_networks = {}
        self.bridges = {}
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())
        self.user_spec = os.environ.get('SCION_USERSPEC', '$LOGNAME')

    def generate(self):
        self._create_networks()
        self._zookeeper_conf()
        for topo_id, topo in self.args.topo_dicts.items():
            base = os.path.join(self.output_base, topo_id.base_dir(self.args.output_dir))
            self._gen_topo(topo_id, topo, base)
        self._write_files()

        tester_gen = TesterGenerator(self._tester_args())
        tester_gen.generate()
        utils_gen = UtilsGenerator(self._utils_args())
        utils_gen.generate()

    def _tester_args(self):
        return TesterGenArgs(self.args)

    def _utils_args(self):
        return UtilsGenArgs(self.args, self.dc_vol_conf['volumes'])

    def _gen_topo(self, topo_id, topo, base):
        self._dispatcher_conf(topo_id, topo, base)
        self._br_conf(topo_id, topo, base)
        self._cs_conf(topo_id, topo, base)
        self._bs_conf(topo_id, topo, base)
        self._ps_conf(topo_id, topo, base)
        self._sciond_conf(topo_id, base)
        self._vol_conf(topo_id)

    def _write_files(self):
        write_file(os.path.join(self.args.output_dir, DOCKER_SCION_CONF),
                   yaml.dump(self.dc_conf, default_flow_style=False))
        write_file(os.path.join(self.args.output_dir, DOCKER_NETWORK_CONF),
                   yaml.dump(self.dc_net_conf, default_flow_style=False))
        write_file(os.path.join(self.args.output_dir, DOCKER_VOLUME_CONF),
                   yaml.dump(self.dc_vol_conf, default_flow_style=False))

    def _vol_conf(self, topo_id):
        self.dc_vol_conf['volumes']['vol_disp_%s' % topo_id.file_fmt()] = None
        self.dc_vol_conf['volumes']['vol_disp_br_%s' % topo_id.file_fmt()] = None
        self.dc_vol_conf['volumes']['vol_sciond_%s' % topo_id.file_fmt()] = None

    def _create_networks(self):
        for network in self.args.networks:
            for elem in self.args.networks[network]:
                if elem not in self.elem_networks:
                    self.elem_networks[elem] = []
                self.elem_networks[elem].append(
                    {'net': str(network), 'ipv4': self.args.networks[network][elem].ip})
            # Create docker networks
            net_pref = "scn_docker" if self.args.in_docker else "scn"
            net_name = "%s_%03d" % (net_pref, len(self.bridges))
            self.bridges[str(network)] = net_name
            self.dc_net_conf['networks'][net_name] = {
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
            'image': 'scion_border',
            'depends_on': [
                'disp_br_%s' % topo_id.file_fmt(),
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'networks': {},
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                'vol_disp_br_%s:/run/shm/dispatcher:rw' % topo_id.file_fmt(),
                self.output_base + '/logs:/share/logs:rw'
            ],
            'command': []
        }
        for k, v in topo.get("BorderRouters", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            entry['command'].append('-id=%s' % k)
            entry['command'].append('-prom=%s' % _prom_addr_br(k, v, self.args.port_gen))
            # Set BR IPs
            in_net = self.elem_networks[k + "_internal"][0]
            entry['networks'][self.bridges[in_net['net']]] = {'ipv4_address': str(in_net['ipv4'])}
            for net in self.elem_networks[k]:
                entry['networks'][self.bridges[net['net']]] = {'ipv4_address': str(net['ipv4'])}
            self.dc_conf['services'][k] = entry

    def _cs_conf(self, topo_id, topo, base):
        image = 'scion_cert_py' if self.args.cert_server == 'py' else 'scion_cert'
        raw_entry = {
            'image': image,
            'depends_on': [
                self._sciond_name(topo_id),
                'disp_%s' % topo_id.file_fmt(),
                'zookeeper'
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'network_mode': 'service:disp_%s' % topo_id.file_fmt(),
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                'vol_disp_%s:/run/shm/dispatcher:rw' % topo_id.file_fmt(),
                'vol_sciond_%s:/run/shm/sciond:rw' % topo_id.file_fmt(),
                self.output_base + '/gen-cache:/share/cache:rw',
                self.output_base + '/logs:/share/logs:rw'
            ],
            'command': []
        }
        for k, v in topo.get("CertificateService", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            if self.args.cert_server == 'py':
                sciond = get_default_sciond_path(ISD_AS(topo["ISD_AS"]))
                entry['command'].append('--spki_cache_dir=cache')
                entry['command'].append('--prom=%s' % _prom_addr_infra(k, v, self.args.port_gen))
                entry['command'].append('--sciond_path=%s' % sciond)
                entry['command'].append(k)
                entry['command'].append('conf')
            self.dc_conf['services'][k] = entry

    def _bs_conf(self, topo_id, topo, base):
        raw_entry = {
            'image': 'scion_beacon_py',
            'depends_on': [
                self._sciond_name(topo_id),
                'disp_%s' % topo_id.file_fmt(),
                'zookeeper'
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'network_mode': 'service:disp_%s' % topo_id.file_fmt(),
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                'vol_disp_%s:/run/shm/dispatcher:rw' % topo_id.file_fmt(),
                'vol_sciond_%s:/run/shm/sciond:rw' % topo_id.file_fmt(),
                self.output_base + '/gen-cache:/share/cache:rw',
                self.output_base + '/logs:/share/logs:rw'
            ],
            'command': [
                '--spki_cache_dir=cache'
            ]
        }
        for k, v in topo.get("BeaconService", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            entry['command'].append('--prom=%s' % _prom_addr_infra(k, v, self.args.port_gen))
            entry['command'].append('--sciond_path=%s' %
                                    get_default_sciond_path(ISD_AS(topo["ISD_AS"])))
            entry['command'].append(k)
            entry['command'].append('conf')
            self.dc_conf['services'][k] = entry

    def _ps_conf(self, topo_id, topo, base):
        image = 'scion_path_py' if self.args.path_server == 'py' else 'scion_path'
        raw_entry = {
            'image': image,
            'depends_on': [
                self._sciond_name(topo_id),
                'disp_%s' % topo_id.file_fmt(),
                'zookeeper'
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'network_mode': 'service:disp_%s' % topo_id.file_fmt(),
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                'vol_disp_%s:/run/shm/dispatcher:rw' % topo_id.file_fmt(),
                'vol_sciond_%s:/run/shm/sciond:rw' % topo_id.file_fmt(),
                self.output_base + '/gen-cache:/share/cache:rw',
                self.output_base + '/logs:/share/logs:rw'
            ],
            'command': [],
        }
        for k, v in topo.get("PathService", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            if self.args.path_server == 'py':
                entry['command'].append('--spki_cache_dir=cache')
                entry['command'].append('--prom=%s' % _prom_addr_infra(k, v, self.args.port_gen))
                entry['command'].append('--sciond_path=%s' %
                                        get_default_sciond_path(ISD_AS(topo["ISD_AS"])))
                entry['command'].append(k)
                entry['command'].append('conf')
            self.dc_conf['services'][k] = entry

    def _zookeeper_conf(self):
        cfg_file = 'docker/zoo-container.cfg'
        entry = {
            'image': 'zookeeper:latest',
            'container_name': 'zookeeper',
            'environment': {
                'ZOO_USER': self.user_spec,
                'ZOO_DATA_DIR': '/var/lib/zookeeper',
                'ZOO_DATA_LOG_DIR': '/dev/shm/zookeeper'
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                os.path.join(
                    self.output_base, self.args.output_dir, cfg_file) + ':/conf/zoo.cfg:rw',
                '/var/lib/docker-zk:/var/lib/zookeeper:rw',
                '/run/shm/docker-zk:/dev/shm/zookeeper:rw'
            ],
            'ports': [
                '2181:2181'
            ]
        }
        self.dc_conf['services']['zookeeper'] = entry
        cfg_path = os.path.join(self.args.output_dir, cfg_file)
        os.makedirs(os.path.dirname(cfg_path))
        copyfile(os.path.join(os.environ['PWD'], cfg_file), cfg_path)

    def _dispatcher_conf(self, topo_id, topo, base):
        # Create dispatcher config
        entry = {
            'image': 'scion_dispatcher',
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'networks': {},
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                '%s:/share/conf:rw' % os.path.join(base, 'dispatcher'),
                self.output_base + '/logs:/share/logs:rw'
            ]
        }

        self._br_dispatcher(copy.deepcopy(entry), topo_id, topo)
        self._infra_dispatcher(copy.deepcopy(entry), topo_id)

    def _br_dispatcher(self, entry, topo_id, topo):
        # Create dispatcher for BR Ctrl Port
        for k in topo.get("BorderRouters", {}):
            ctrl_net = self.elem_networks[k + "_ctrl"][0]
            ctrl_ip = str(ctrl_net['ipv4'])
            entry['networks'][self.bridges[ctrl_net['net']]] = {'ipv4_address': ctrl_ip}
        name = 'disp_br_%s' % topo_id.file_fmt()
        entry['container_name'] = name
        entry['volumes'].append('vol_disp_br_%s:/run/shm/dispatcher:rw' % topo_id.file_fmt())
        entry['environment']['ZLOG_CFG'] = "/share/conf/disp_br.zlog.conf"
        self.dc_conf['services'][name] = entry
        # Write log config file
        cfg = "%s/dispatcher/%s.zlog.conf" % (topo_id.base_dir(self.args.output_dir), "disp_br")
        tmpl = Template(read_file("topology/zlog.tmpl"))
        write_file(cfg, tmpl.substitute(name="dispatcher", elem=name))

    def _infra_dispatcher(self, entry, topo_id):
        # Create dispatcher for Infra
        net = self.elem_networks["disp" + topo_id.file_fmt()][0]
        ip = str(net['ipv4'])
        entry['networks'][self.bridges[net['net']]] = {'ipv4_address': ip}
        name = 'disp_%s' % topo_id.file_fmt()
        entry['container_name'] = name
        entry['volumes'].append('vol_disp_%s:/run/shm/dispatcher:rw' % topo_id.file_fmt())
        self.dc_conf['services'][name] = entry
        # Write log config file
        cfg = "%s/dispatcher/%s.zlog.conf" % (topo_id.base_dir(self.args.output_dir), "dispatcher")
        tmpl = Template(read_file("topology/zlog.tmpl"))
        write_file(cfg, tmpl.substitute(name="dispatcher", elem=name))

    def _sciond_conf(self, topo_id, base):
        name = self._sciond_name(topo_id)
        image = 'scion_sciond_py' if self.args.sciond == 'py' else 'scion_sciond'
        entry = {
            'image': image,
            'container_name': name,
            'depends_on': [
                'disp_%s' % topo_id.file_fmt()
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                'vol_disp_%s:/run/shm/dispatcher:rw' % topo_id.file_fmt(),
                'vol_sciond_%s:/run/shm/sciond:rw' % topo_id.file_fmt(),
                '%s:/share/conf:ro' % os.path.join(base, 'endhost'),
                self.output_base + '/gen-cache:/share/cache:rw',
                self.output_base + '/logs:/share/logs:rw'
            ],
        }
        if self.args.sciond == 'py':
            entry['command'] = [
                '--api-addr=%s' % os.path.join(SCIOND_API_SOCKDIR, "%s.sock" % name),
                '--log_dir=logs',
                '--spki_cache_dir=cache',
                name,
                'conf'
            ]
        self.dc_conf['services'][name] = entry

    def _sciond_name(self, topo_id):
        return 'sd' + topo_id.file_fmt()
