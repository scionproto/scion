# Copyright 2014 ETH Zurich
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
"""
:mod:`go` --- SCION topology go generator
=============================================
"""
# Stdlib
import os
import toml

# SCION
from lib.defines import SCIOND_API_SOCKDIR
from lib.util import write_file
from topology.common import COMMON_DIR


class GoGenerator(object):
    def __init__(self, out_dir, topo_dicts, docker):
        self.out_dir = out_dir
        self.topo_dicts = topo_dicts
        self.docker = docker

    def generate_ps(self):
        for topo_id, topo in self.topo_dicts.items():
            for k, v in topo.get("PathService", {}).items():
                # only a single Go-PS per AS is currently supported
                if k.endswith("-1"):
                    base = topo_id.base_dir(self.out_dir)
                    ps_conf = self._build_ps_conf(topo_id, topo["ISD_AS"], base, k)
                    write_file(os.path.join(base, k, "psconfig.toml"), toml.dumps(ps_conf))

    def _build_ps_conf(self, topo_id, ia, base, name):
        config_dir = '/share/conf' if self.docker else os.path.join(base, name)
        log_dir = '/share/logs' if self.docker else 'logs'
        db_dir = '/share/cache' if self.docker else 'gen-cache'
        raw_entry = {
            'general': {
                'ID': name,
                'ConfigDir': config_dir,
                'ReconnectToDispatcher': True,
            },
            'logging': {
                'file': {
                    'Path': os.path.join(log_dir, "%s.log" % name),
                    'Level': 'debug',
                },
                'console': {
                    'Level': 'crit',
                },
            },
            'trust': {
                'TrustDB': os.path.join(db_dir, '%s.trust.db' % name),
            },
            'infra': {
                'Type': "PS"
            },
            'ps': {
                'PathDB': {
                    'Backend': 'sqlite',
                    'Connection': os.path.join(db_dir, '%s.path.db' % name),
                },
                'SegSync': True,
            },
        }
        return raw_entry

    def generate_sciond(self):
        for topo_id, topo in self.topo_dicts.items():
            base = topo_id.base_dir(self.out_dir)
            sciond_conf = self._build_sciond_conf(topo_id, topo["ISD_AS"], base)
            write_file(os.path.join(base, COMMON_DIR, "sciond.toml"), toml.dumps(sciond_conf))

    def _build_sciond_conf(self, topo_id, ia, base):
        name = self._sciond_name(topo_id)
        config_dir = '/share/conf' if self.docker else os.path.join(base, COMMON_DIR)
        log_dir = '/share/logs' if self.docker else 'logs'
        db_dir = '/share/cache' if self.docker else 'gen-cache'
        raw_entry = {
            'general': {
                'ID': name,
                'ConfigDir': config_dir,
                'ReconnectToDispatcher': True,
            },
            'logging': {
                'file': {
                    'Path': os.path.join(log_dir, "%s.log" % name),
                    'Level': 'debug',
                },
                'console': {
                    'Level': 'crit',
                },
            },
            'trust': {
                'TrustDB': os.path.join(db_dir, '%s.trust.db' % name),
            },
            'sd': {
                'Reliable': os.path.join(SCIOND_API_SOCKDIR, "%s.sock" % name),
                'Unix': os.path.join(SCIOND_API_SOCKDIR, "%s.unix" % name),
                'Public': '%s,[127.0.0.1]:0' % ia,
                'PathDB': {
                    'Connection': os.path.join(db_dir, '%s.path.db' % name),
                },
            },
        }
        return raw_entry

    def _sciond_name(self, topo_id):
        return 'sd' + topo_id.file_fmt()
