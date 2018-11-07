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
import os
# External packages
import yaml
# SCION
from lib.util import write_file
from topology.common import ArgsBase

DOCKER_TESTER_CONF = 'testers-dc.yml'
DOCKER_UTIL_CONF = 'utils-dc.yml'
DEFAULT_DC_NETWORK = "172.18.0.0/24"


class TesterGenArgs(ArgsBase):
    pass


class UtilsGenArgs(ArgsBase):
    def __init__(self, args, volumes):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param list volumes: The compose volume config
        """
        super().__init__(args)
        self.volumes = volumes


class TesterGenerator(object):
    def __init__(self, args):
        """
        :param TesterGenArgs args: Contains the passed command line arguments.
        """
        self.args = args
        self.dc_tester_conf = {'version': '3', 'services': {}}
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())

    def generate(self):
        for topo_id in self.args.topo_dicts:
            self._test_conf(topo_id)
        write_file(os.path.join(self.args.output_dir, DOCKER_TESTER_CONF),
                   yaml.dump(self.dc_tester_conf, default_flow_style=False))

    def _test_conf(self, topo_id):
        cntr_base = '/home/scion/go/src/github.com/scionproto/scion'
        entry = {
            'image': 'scion_app_builder',
            'container_name': 'tester',
            'environment': [
                'PYTHONPATH=python/:',
                'SCION_UID',
                'SCION_GID',
                'DOCKER_GID'
            ],
            'volumes': [
                'vol_disp_%s:/run/shm/dispatcher:rw' % topo_id.file_fmt(),
                'vol_sciond_%s:/run/shm/sciond:rw' % topo_id.file_fmt(),
                self.output_base + '/logs:' + cntr_base + '/logs:rw',
                self.output_base + '/gen:' + cntr_base + '/gen:rw',
                self.output_base + '/gen-certs:' + cntr_base + '/gen-certs:rw'
            ],
            'user': 'root',
            'command': [
                '-c',
                'tail -f /dev/null'
            ]
        }
        name = 'tester_%s' % topo_id.file_fmt()
        entry['container_name'] = name
        self.dc_tester_conf['services'][name] = entry


class UtilsGenerator(object):
    """
    :param UtilsGenArgs args: Contains the passed command line arguments.
    """
    def __init__(self, args):
        self.args = args
        self.dc_util_conf = {'version': '3', 'services': {}, 'networks': {}}
        self.user_spec = os.environ.get('SCION_USERSPEC', '$LOGNAME')

    def generate(self):
        self._utils_conf()
        self._net_conf()
        write_file(os.path.join(self.args.output_dir, DOCKER_UTIL_CONF),
                   yaml.dump(self.dc_util_conf, default_flow_style=False))

    def _net_conf(self):
        default_net = {'ipam': {'config': [{'subnet': DEFAULT_DC_NETWORK}]}}
        self.dc_util_conf['networks']['default'] = default_net

    def _utils_conf(self):
        entry_chown = {
            'image': 'busybox',
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro'
            ],
            'command': 'chown -R ' + self.user_spec + ' /run/shm/volumes/.'
        }
        entry_clean = {
            'image': 'busybox',
            'volumes': [],
            'command': 'sh -c "find /run/shm/volumes -type s -print0 | xargs -r0 rm -v"'
        }
        for volume in self.args.volumes:
            entry_chown['volumes'].append('%s:/run/shm/volumes/%s' % (volume, volume))
            entry_clean['volumes'].append('%s:/run/shm/volumes/%s' % (volume, volume))
        self.dc_util_conf['services']['chowner'] = entry_chown
        self.dc_util_conf['services']['cleaner'] = entry_clean
