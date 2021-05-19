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

import logging
import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, MutableMapping

import toml
from plumbum import local
import yaml
from plumbum.cmd import docker
from plumbum.path.local import LocalPath

from acceptance.common.log import LogExec
from python.lib import scion_addr
from python.lib.scion_addr import ISD_AS

logger = logging.getLogger(__name__)


class SCION(ABC):
    """ SCION is the base class for interacting with the infrastructure. """
    scion_sh = local['./scion.sh']
    end2end = local['./bin/end2end_integration']

    @abstractmethod
    def topology(self, topo_file: str, *args: str):
        """ Create the topology files by invoking scion.sh
        :param topo_file: The .topo file passed with -c.
        :param args: List of optional arguments.
        """
        pass

    @LogExec(logger, 'running topology')
    def run(self):
        """ Run the scion infrastructure. """
        self.scion_sh('run', 'nobuild')

    @abstractmethod
    def execute(self, isd_as: ISD_AS, cmd: str, *args: str) -> str:
        """ Execute command as host in specified AS
        :param isd_as: The ISD-AS of the AS to run the command in.
        :param cmd: The command to execute.
        :param args: List of optional arguments.
        """
        pass

    def status(self):
        """ Print the scion infrastructure status. """
        self.scion_sh('status')

    def stop(self):
        """ Stop the scion infrastructure. """
        self.scion_sh('stop')

    @abstractmethod
    def _send_signals(self, svc_names: List[str], sig: str):
        """
        Send the signal to all service names.

        :param svc_names: List of service names.
        :param sig: signal string (e.g. SIGHUP, SIGKILL)
        """
        pass

    def kill_svc(self, svc_names: List[str]):
        """ Send SIGKILL to services by name. """
        self._send_signals(svc_names, "SIGKILL")

    def reload_svc(self, svc_names: List[str]):
        """ Send SIGHUP to services by name. """
        self._send_signals(svc_names, "SIGHUP")

    @LogExec(logger, 'end2end test')
    def run_end2end(self, *args, expect_fail=False):
        self._run_end2end(*args, code=1 if expect_fail else 0)

    @abstractmethod
    def _run_end2end(self, *args, code=0):
        """
        Run the end2end integration test.
        :param code: The expected return code.
        """
        pass


def update_toml(change_dict: Dict[str, Any], files: LocalPath):
    """ Overwrite or set the values in the TOML files with the specified changes.

    Args:
        change_dict: Change dictionary containing a dot separated path
          to the TOML value. E.g. {"log.console.level": "debug"} result in the
          TOML file with the following set:

          [log.console]
              level = "debug"
        files: names of file or files to update.

    Raises:
        TypeError: Argument file is of invalid type
        TomlDecodeError: Error while decoding TOML
        IOError / FileNotFoundError: File path is not valid
    """
    for f in files:
        t = toml.load(f)
        for path, val in change_dict.items():
            merge_dict(path_to_dict(path, val), t)
        toml.dump(t, f)


def update_json(change_dict: Dict[str, Any], files: LocalPath):
    """ Overwrite or set the values in the JSON files with the specified changes.

    Args:
        change_dict: Change dictionary containing a dot separated path
          to the JSON value.
        files: names of file or files to update.

    Raises:
        IOError / FileNotFoundError: File path is not valid
    """
    for file in files:
        with open(file, "r") as f:
            t = json.load(f)
        for path, val in change_dict.items():
            merge_dict(path_to_dict(path, val), t)
        with open(file, "w") as f:
            json.dump(t, f, indent=2)


class SCIONDocker(SCION):
    """
    SCIONDocker is used for interacting with the dockerized
    scion infrastructure.
    """
    tools_dc = local['./tools/dc']

    @LogExec(logger, "creating dockerized topology")
    def topology(self, topo_file: str, *args: str):
        """ Create the dockerized topology files. """
        self.scion_sh('topology', '-c', topo_file, '-d', *args)

    def execute(self, isd_as: ISD_AS, cmd: str, *args: str) -> str:
        expanded = []
        for arg in args:
            if str(arg).startswith('gen/'):
                arg = '/share/' + arg
            expanded.append(arg)
        return docker('exec', 'tester_%s' % isd_as.file_fmt(), cmd, *expanded)

    def _send_signals(self, svc_names: List[str], sig: str):
        for svc_name in svc_names:
            self.tools_dc('scion', 'kill', '-s', sig, 'scion_%s' % svc_name)

    def _run_end2end(self, *args, code=0):
        self.end2end('-d', *args, retcode=code)


class ASList(object):
    """
    ASList is a list of AS separated by core and non-core ASes. It can be loaded
    from the as_list.yml file created by the topology generator.
    """
    def __init__(self, cores: List[scion_addr.ISD_AS], non_cores: List[scion_addr.ISD_AS]):
        self.cores = cores
        self.non_cores = non_cores

    @property
    def all(self) -> List[scion_addr.ISD_AS]:
        return self.cores + self.non_cores

    @staticmethod
    def load(file: str = "gen/as_list.yml") -> "ASList":
        with open(file, "r") as content:
            data = yaml.load(content, yaml.Loader)
        cores = [scion_addr.ISD_AS(raw) for raw in data["Core"]]
        non_cores = [scion_addr.ISD_AS(raw) for raw in data["Non-core"]]
        return ASList(cores, non_cores)


def sciond_addr(isd_as: ISD_AS, port: bool = True, gen_dir: str = "gen"):
    """
    Return the SCION Daemon address for the given AS.
    """
    with open("%s/sciond_addresses.json" % gen_dir) as f:
        addrs = json.load(f)
        ip = addrs[str(isd_as)]
        if not port:
            return ip
        if ':' in ip:
            return '[%s]:30255' % ip
        return '%s:30255' % ip


def path_to_dict(path: str, val: Any) -> Dict:
    """
    Convert a path 'a.b.c' and value val to a nested dictionary of form
    {'a': {'b': {'c': val}}}
    """
    d = val
    for k in reversed(path.split('.')):
        d = {k: d}
    return d


def merge_dict(change_dict: Dict[str, Any], orig_dict: MutableMapping[str, Any]):
    """
    Merge changes into the original dictionary. Leaf values in the change dict
    overwrite the values in the original dictionary.
    """
    for k, v in change_dict.items():
        if not orig_dict.get(k):
            orig_dict[k] = v
        else:
            if isinstance(orig_dict[k], dict) and isinstance(v, dict):
                merge_dict(v, orig_dict[k])
            else:
                orig_dict[k] = v
