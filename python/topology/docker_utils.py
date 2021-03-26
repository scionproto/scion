# Copyright 2018 ETH Zurich
# Copyright 2019 ETH Zurich, Anapaya Systems
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
from python.lib.util import write_file
from python.topology.common import (
    ArgsBase,
    docker_image,
    remote_nets,
)


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
    def __init__(self, args):
        """
        :param UtilsGenArgs args: Contains the passed command line arguments.
        """
        self.args = args
        self.dc_conf = args.dc_conf
        self.user = '%d:%d' % (os.getuid(), os.getgid())
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
            'network_mode': 'none',
            'volumes': [
                '/etc/passwd:/etc/passwd:ro',
                '/etc/group:/etc/group:ro'
            ],
            'command': 'chown -R ' + self.user + ' /mnt/volumes'
        }
        for volume in self.dc_conf['volumes']:
            entry_chown['volumes'].append('%s:/mnt/volumes/%s' % (volume, volume))
        self.dc_conf['services']['utils_chowner'] = entry_chown

    def _test_conf(self, topo_id):
        cntr_base = '/share'
        name = 'tester_%s' % topo_id.file_fmt()
        entry = {
            'image': docker_image(self.args, 'tester'),
            'container_name': 'tester_%s' % topo_id.file_fmt(),
            'depends_on': ['scion_disp_%s' % name],
            'privileged': True,
            'entrypoint': 'sh tester.sh',
            'environment': {},
            # 'user': self.user,
            'volumes': [
                'vol_scion_disp_%s:/run/shm/dispatcher:rw' % name,
                self.output_base + '/logs:' + cntr_base + '/logs:rw',
                self.output_base + '/gen:' + cntr_base + '/gen:rw',
                self.output_base + '/gen-certs:' + cntr_base + '/gen-certs:rw'
            ],
            'network_mode': 'service:scion_disp_%s' % name,
        }
        net = self.args.networks[name][0]
        ipv = 'ipv4'
        if ipv not in net:
            ipv = 'ipv6'
        disp_net = self.args.networks[name][0]
        entry['environment']['SCION_LOCAL_ADDR'] = str(disp_net[ipv])
        sciond_net = self.args.networks['sd%s' % topo_id.file_fmt()][0]
        entry['environment']['SCION_DAEMON'] = '%s:30255' % sciond_net[ipv]
        if self.args.sig:
            # If the tester container needs to communicate to the SIG, it needs the SIG_IP and
            # REMOTE_NETS which are the remote subnets that need to be routed through the SIG.
            # net information for the connected SIG
            sig_net = self.args.networks['sig%s' % topo_id.file_fmt()][0]
            entry['environment']['SIG_IP'] = str(sig_net[ipv])
            entry['environment']['REMOTE_NETS'] = remote_nets(self.args.networks, topo_id)
        self.dc_conf['services'][name] = entry

    def _sig_testing_conf(self):
        text = ''
        for topo_id in self.args.topo_dicts:
            net = self.args.networks['tester_%s' % topo_id.file_fmt()][0]
            ipv = 'ipv4'
            if ipv not in net:
                ipv = 'ipv6'
            ip = net[ipv]
            text += str(topo_id) + ' ' + str(ip) + '\n'
            conf_path = os.path.join(self.args.output_dir, 'sig-testing.conf')
            write_file(conf_path, text)
