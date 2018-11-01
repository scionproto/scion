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

DOCKER_TESTER_CONF = 'testers-dc.yml'


class UtilsGenerator(object):
    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.dc_tester_conf = {'version': '3', 'services': {}}
        self.output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())

    def generate(self):
        self._test_conf()
        write_file(os.path.join(self.out_dir, DOCKER_TESTER_CONF),
                   yaml.dump(self.dc_tester_conf, default_flow_style=False))

    def _test_conf(self):
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
                '/run/shm/dispatcher:/run/shm/dispatcher:rw',
                '/run/shm/sciond:/run/shm/sciond:rw',
                self.output_base + '/logs:/home/scion/go/src/github.com/scionproto/scion/logs:rw',
                self.output_base + '/gen:/home/scion/go/src/github.com/scionproto/scion/gen:rw',
                self.output_base + '/gen-certs:\
                /home/scion/go/src/github.com/scionproto/scion/gen-certs:rw'
            ],
            'user': 'root',
            'command': [
                '-c',
                'tail -f /dev/null'
            ]
        }
        self.dc_tester_conf['services']['tester'] = entry
