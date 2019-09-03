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
:mod:`cert` --- SCION topology certificate generator
=============================================
"""
import os
from collections import defaultdict

from plumbum import local

from topology.common import ArgsTopoConfig, srv_iter


class CertGenArgs(ArgsTopoConfig):
    pass


class CertGenerator(object):
    def __init__(self, args):
        """
        :param CertGenArgs args: Contains the passed command line
        arguments and the parsed topo config.
        """
        self.args = args
        self.pki = local['./bin/scion-pki']
        self.core_count = defaultdict(int)

    def generate(self, topo_dicts):
        self.pki('tmpl', 'topo', self.args.topo_config, '-d', self.args.output_dir)
        self.pki('keys', 'gen', '*', '-d', self.args.output_dir)
        self.pki('trc', 'gen', '*', '-d', self.args.output_dir)
        self.pki('certs', 'gen', '*', '-d', self.args.output_dir)
        self.pki('certs', 'customers', '*', '-d', self.args.output_dir)
        self._sym_links(topo_dicts)

    def _sym_links(self, topo_dicts):
        # Symlink the trcs into the AS certs dir.
        for topo_id in topo_dicts:
            as_dir = local.path(topo_id.base_dir(self.args.output_dir))
            for trc in as_dir.dirname // 'trcs/*':
                os.symlink(os.path.join('../../trcs', trc.name), as_dir / 'certs' / trc.name)
        # Symlink the certs and key dir for all elements.
        for topo_id, as_topo, base in srv_iter(
                topo_dicts, self.args.output_dir, common=True):
            elem_dir = local.path(base)
            as_dir = elem_dir.dirname
            os.symlink('../certs', elem_dir / 'certs')
            os.symlink('../keys', elem_dir / 'keys')
        # Symlink the customers dir for all certificate servers.
        for topo_id, as_topo in topo_dicts.items():
            base = local.path(topo_id.base_dir(self.args.output_dir))
            for elem in as_topo["CertificateService"]:
                os.symlink('../customers', base / elem / 'customers')
