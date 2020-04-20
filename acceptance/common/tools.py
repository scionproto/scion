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

import sys

from contextlib import redirect_stderr
from plumbum.cmd import (
    docker,
    docker_compose,
    mkdir,
)
from plumbum import local

SCION_DC_FILE = 'gen/scion-dc.yml'
DC_PROJECT = 'acceptance_scion'


def container_ip(container_name: str) -> str:
    """Returns the ip of the given container"""
    return docker('inspect', '-f', '{{range .NetworkSettings.Networks}}'
                  '{{.IPAddress}}{{end}}', container_name).rstrip()


class DC(object):

    def __init__(self,
                 base_dir: str,
                 project: str = DC_PROJECT,
                 compose_file: str = SCION_DC_FILE):
        self.base_dir = base_dir
        self.project = project
        self.compose_file = compose_file

    def __call__(self, *args, **kwargs) -> str:
        """Runs docker compose with the given arguments"""
        with local.env(BASE_DIR=self.base_dir, COMPOSE_FILE=self.compose_file):
            with redirect_stderr(sys.stdout):
                return docker_compose('-p', self.project, '--no-ansi',
                                      *args, **kwargs)

    def collect_logs(self, out_dir: str = 'logs/docker'):
        """Collects the logs from the services into the given directory"""
        out_p = local.path(out_dir)
        mkdir('-p', out_p)
        for svc in self('config', '--services').splitlines():
            dst_f = out_p / '%s.log' % svc
            with local.env(BASE_DIR=self.base_dir, COMPOSE_FILE=self.compose_file):
                with redirect_stderr(sys.stdout):
                    (docker_compose['-p', self.project, '--no-ansi', 'logs', svc] > dst_f)()
