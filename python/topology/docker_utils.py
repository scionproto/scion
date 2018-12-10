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
# SCION
from lib.util import write_file
from topology.common import ArgsBase, docker_image, remote_nets


class DockerUtilsGenArgs(ArgsBase):
    def __init__(self, args, dc_conf, bridges, networks):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict dc_conf: The compose config
        :param dict bridges: The generated bridges from DockerGenerator.
        :param dict networks: The generated networks from DockerGenerator.
        """
        super().__init__(args)
        self.dc_conf = dc_conf
        self.bridges = bridges
        self.networks = networks


class DockerUtilsGenerator(object):
    """
    :param UtilsGenArgs args: Contains the passed command line arguments.
    """
    def __init__(self, args):
        self.args = args
        self.dc_conf = args.dc_conf
        self.user_spec = os.environ.get('SCION_USERSPEC', '$LOGNAME')
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())

    def generate(self):
        self._utils_conf()
        for topo_id in self.args.topo_dicts:
            self._test_conf(topo_id)
        if self.args.sig:
            self._sig_testing_conf()
        return self.dc_conf

    def _utils_conf(self):
        entry_chown = {
            'image': 'busybox',
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro'
            ],
            'command': 'chown -R ' + self.user_spec + ' /mnt/volumes'
        }
        entry_clean = {
            'image': 'busybox',
            'volumes': [],
            'command': 'sh -c "find /mnt/volumes -type s -print0 | xargs -r0 rm -v"'
        }
        for volume in self.dc_conf['volumes']:
            entry_chown['volumes'].append('%s:/mnt/volumes/%s' % (volume, volume))
            entry_clean['volumes'].append('%s:/mnt/volumes/%s' % (volume, volume))
        self.dc_conf['services']['utils_chowner'] = entry_chown
        self.dc_conf['services']['utils_cleaner'] = entry_clean

    def _test_conf(self, topo_id):
        docker = 'docker_' if self.args.in_docker else ''
        cntr_base = '/home/scion/go/src/github.com/scionproto/scion'
        name = 'tester_%s' % topo_id.file_fmt()
        entry = {
            'image': docker_image(self.args, 'tester'),
            'container_name': 'tester_%s%s' % (docker, topo_id.file_fmt()),
            'privileged': True,
            'entrypoint': './tester.sh',
            'environment': {},
            'volumes': [
                'vol_scion_%sdisp_%s:/run/shm/dispatcher:rw' % (docker, topo_id.file_fmt()),
                'vol_scion_%ssciond_%s:/run/shm/sciond:rw' % (docker, topo_id.file_fmt()),
                self.output_base + '/logs:' + cntr_base + '/logs:rw',
                self.output_base + '/gen:' + cntr_base + '/gen:rw',
                self.output_base + '/gen-certs:' + cntr_base + '/gen-certs:rw'
            ],
            'networks': {}
        }
        if self.args.sig:
            # If the tester container needs to communicate to the SIG, it needs the SIG_IP and
            # REMOTE_NETS which are the remote subnets that need to be routed through the SIG.
            # net information for the connected SIG
            sig_net = self.args.networks['sig_%s' % topo_id.file_fmt()][0]
            net = self.args.networks[name][0]
            bridge = self.args.bridges[net['net']]
            entry['networks'][bridge] = {'ipv4_address': str(net['ipv4'])}
            entry['environment']['SIG_IP'] = str(sig_net['ipv4'])
            entry['environment']['REMOTE_NETS'] = remote_nets(self.args.networks, topo_id)
        self.dc_conf['services'][name] = entry

    def _sig_testing_conf(self):
        text = ''
        for topo_id in self.args.topo_dicts:
            ip = self.args.networks['sig_%s' % topo_id.file_fmt()][0]['ipv4']
            text += str(topo_id) + ' ' + str(ip) + '\n'
            conf_path = os.path.join(self.args.output_dir, 'sig-testing.conf')
            write_file(conf_path, text)
