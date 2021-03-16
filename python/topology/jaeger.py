# Copyright 2019 Anapaya Systems
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

import os
import yaml

from python.lib.util import write_file
from python.topology.common import (
    ArgsTopoDicts,
)

JAEGER_DC = 'jaeger-dc.yml'


class JaegerGenArgs(ArgsTopoDicts):
    pass


class JaegerGenerator(object):

    def __init__(self, args):
        self.args = args
        output_base = os.environ.get('SCION_OUTPUT_BASE', os.getcwd())
        self.local_jaeger_dir = os.path.join('traces')
        self.docker_jaeger_dir = os.path.join(output_base, self.local_jaeger_dir)

    def generate(self):
        dc_conf = self._generate_dc()
        os.makedirs(os.path.join(self.local_jaeger_dir, 'data'), exist_ok=True)
        os.makedirs(os.path.join(self.local_jaeger_dir, 'key'), exist_ok=True)
        write_file(os.path.join(self.args.output_dir, JAEGER_DC),
                   yaml.dump(dc_conf, default_flow_style=False))

    def _generate_dc(self):
        name = 'jaeger'
        entry = {
            'version': '2',
            'services': {
                'jaeger': {
                    'image': 'jaegertracing/all-in-one:1.22.0',
                    'container_name': name,
                    'user': '%s:%s' % (str(os.getuid()), str(os.getgid())),
                    'ports': [
                        '6831:6831/udp',
                        '16686:16686'
                    ],
                    'environment': [
                        'SPAN_STORAGE_TYPE=badger',
                        'BADGER_EPHEMERAL=false',
                        'BADGER_DIRECTORY_VALUE=/badger/data',
                        'BADGER_DIRECTORY_KEY=/badger/key',
                    ],
                    'volumes': [
                        '%s:/badger:rw' % self.docker_jaeger_dir,
                    ],
                }
            }
        }
        return entry
