# Copyright 2018 ETH Zurich
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
from topology.common import _prom_addr_br, _prom_addr_infra

DOCKER_CONF = 'scion-dc.yml'
DEFAULT_DOCKER_NETWORK = "172.18.0.0/24"


class DockerGenerator(object):
    def __init__(self, out_dir, topo_dicts, sd, ps):
        self.out_dir = out_dir
        self.topo_dicts = topo_dicts
        self.sd = sd
        self.ps = ps
        self.dc_conf = {'version': '3', 'services': {}, 'networks': {}}
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())
        self.user_spec = os.environ.get('SCION_USERSPEC', '$LOGNAME')

    def generate(self):
        self._base_conf()
        self._zookeeper_conf()
        self._dispatcher_conf()
        for topo_id, topo in self.topo_dicts.items():
            base = os.path.join(self.output_base, topo_id.base_dir(self.out_dir))
            self._br_conf(topo, base)
            self._cs_conf(topo_id, topo, base)
            self._bs_conf(topo_id, topo, base)
            self._ps_conf(topo_id, topo, base)
            self._sciond_conf(topo_id, base)
        write_file(os.path.join(self.out_dir, DOCKER_CONF),
                   yaml.dump(self.dc_conf, default_flow_style=False))

    def _base_conf(self):
        default_net = {'ipam': {'config': [{'subnet': DEFAULT_DOCKER_NETWORK}]}}
        self.dc_conf['networks']['default'] = default_net

    def _br_conf(self, topo, base):
        raw_entry = {
            'image': 'scion_border',
            'restart': 'always',
            'network_mode': 'host',
            'depends_on': [
                'dispatcher',
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                '/run/shm/dispatcher:/run/shm/dispatcher:rw',
                self.output_base + '/logs:/share/logs:rw'
            ],
            'command': []
        }
        for k, v in topo.get("BorderRouters", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            entry['command'].append('-id=%s' % k)
            entry['command'].append('-prom=%s' % _prom_addr_br(v))
            self.dc_conf['services'][k] = entry

    def _cs_conf(self, topo_id, topo, base):
        raw_entry = {
            'image': 'scion_cert_py',
            'restart': 'always',
            'depends_on': [
                self._sciond_name(topo_id),
                'dispatcher',
                'zookeeper'
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                '/run/shm/dispatcher:/run/shm/dispatcher:rw',
                '/run/shm/sciond:/run/shm/sciond:rw',
                self.output_base + '/gen-cache:/share/cache:rw',
                self.output_base + '/logs:/share/logs:rw'
            ],
            'command': [
                '--spki_cache_dir=cache'
            ]
        }
        for k, v in topo.get("CertificateService", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            entry['command'].append('--prom=%s' % _prom_addr_infra(v))
            entry['command'].append('--sciond_path=%s' %
                                    get_default_sciond_path(ISD_AS(topo["ISD_AS"])))
            entry['command'].append(k)
            entry['command'].append('conf')
            self.dc_conf['services'][k] = entry

    def _bs_conf(self, topo_id, topo, base):
        raw_entry = {
            'image': 'scion_beacon_py',
            'restart': 'always',
            'depends_on': [
                self._sciond_name(topo_id),
                'dispatcher',
                'zookeeper'
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                '/run/shm/dispatcher:/run/shm/dispatcher:rw',
                '/run/shm/sciond:/run/shm/sciond:rw',
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
            entry['command'].append('--prom=%s' % _prom_addr_infra(v))
            entry['command'].append('--sciond_path=%s' %
                                    get_default_sciond_path(ISD_AS(topo["ISD_AS"])))
            entry['command'].append(k)
            entry['command'].append('conf')
            self.dc_conf['services'][k] = entry

    def _ps_conf(self, topo_id, topo, base):
        image = 'scion_path_py' if self.ps == 'py' else 'scion_path'
        raw_entry = {
            'image': image,
            'restart': 'always',
            'depends_on': [
                self._sciond_name(topo_id),
                'dispatcher',
                'zookeeper'
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                '/run/shm/dispatcher:/run/shm/dispatcher:rw',
                '/run/shm/sciond:/run/shm/sciond:rw',
                self.output_base + '/gen-cache:/share/cache:rw',
                self.output_base + '/logs:/share/logs:rw'
            ],
            'command': [],
        }
        for k, v in topo.get("PathService", {}).items():
            entry = copy.deepcopy(raw_entry)
            entry['container_name'] = k
            entry['volumes'].append('%s:/share/conf:ro' % os.path.join(base, k))
            if self.ps == 'py':
                entry['command'].append('--spki_cache_dir=cache')
                entry['command'].append('--prom=%s' % _prom_addr_infra(v))
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
            'restart': 'always',
            'environment': {
                'ZOO_USER': self.user_spec,
                'ZOO_DATA_DIR': '/var/lib/zookeeper',
                'ZOO_DATA_LOG_DIR': '/dev/shm/zookeeper'
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                os.path.join(self.output_base, self.out_dir, cfg_file) + ':/conf/zoo.cfg:rw',
                '/var/lib/docker-zk:/var/lib/zookeeper:rw',
                '/run/shm/docker-zk:/dev/shm/zookeeper:rw'
            ],
            'ports': [
                '2181:2181'
            ]
        }
        self.dc_conf['services']['zookeeper'] = entry
        cfg_path = os.path.join(self.out_dir, cfg_file)
        os.makedirs(os.path.dirname(cfg_path))
        copyfile(os.path.join(os.environ['PWD'], cfg_file), cfg_path)

    def _dispatcher_conf(self):
        entry = {
            'image': 'scion_dispatcher',
            'container_name': 'dispatcher',
            'restart': 'always',
            'network_mode': 'host',
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                '/run/shm/dispatcher:/run/shm/dispatcher:rw',
                self.output_base + '/gen/dispatcher:/share/conf:rw',
                self.output_base + '/logs:/share/logs:rw'
            ]
        }
        self.dc_conf['services']['dispatcher'] = entry

        # Create dispatcher config
        tmpl = Template(read_file("topology/zlog.tmpl"))
        cfg = self.out_dir + "/dispatcher/dispatcher.zlog.conf"
        write_file(cfg, tmpl.substitute(name="dispatcher", elem="dispatcher"))

    def _sciond_conf(self, topo_id, base):
        name = self._sciond_name(topo_id)
        image = 'scion_sciond_py' if self.sd == 'py' else 'scion_sciond'
        entry = {
            'image': image,
            'restart': 'always',
            'container_name': name,
            'depends_on': [
                'dispatcher',
            ],
            'environment': {
                'SU_EXEC_USERSPEC': self.user_spec,
            },
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro',
                '/run/shm/dispatcher:/run/shm/dispatcher:rw',
                '/run/shm/sciond:/run/shm/sciond:rw',
                '%s:/share/conf:ro' % os.path.join(base, 'endhost'),
                self.output_base + '/gen-cache:/share/cache:rw',
                self.output_base + '/logs:/share/logs:rw'
            ],
        }
        if self.sd == 'py':
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
