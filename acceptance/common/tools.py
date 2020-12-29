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

import subprocess
import sys

from contextlib import redirect_stderr
import plumbum
from plumbum import cmd

SCION_DC_FILE = "gen/scion-dc.yml"
DC_PROJECT = "scion"


def container_ip(container_name: str) -> str:
    """Returns the ip of the given container"""
    return cmd.docker("inspect", "-f", "{{range .NetworkSettings.Networks}}"
                      "{{.IPAddress}}{{end}}", container_name).rstrip()


class DC(object):

    def __init__(self,
                 project: str = DC_PROJECT,
                 compose_file: str = SCION_DC_FILE):
        self.project = project
        self.compose_file = compose_file

    def __call__(self, *args, **kwargs) -> str:
        """Runs docker compose with the given arguments"""
        with redirect_stderr(sys.stdout):
            return cmd.docker_compose("-f", self.compose_file, "-p", self.project, "--no-ansi",
                                      *args, **kwargs)

    def collect_logs(self, out_dir: str = "logs/docker"):
        """Collects the logs from the services into the given directory"""
        out_p = plumbum.local.path(out_dir)
        cmd.mkdir("-p", out_p)
        for svc in self("config", "--services").splitlines():
            dst_f = out_p / "%s.log" % svc
            with open(dst_f, "w") as log_file:
                cmd.docker.run(args=("logs", svc), stdout=log_file,
                               stderr=subprocess.STDOUT, retcode=None)
