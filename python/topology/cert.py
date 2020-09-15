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
import base64
import os
from collections import defaultdict

from plumbum import local

from python.lib.util import write_file
from python.topology.common import ArgsTopoConfig


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
        self.pki('testcrypto', '-t', self.args.topo_config, '-o', self.args.output_dir)
        self._master_keys(topo_dicts)
        self._copy_files(topo_dicts)

    def _master_keys(self, topo_dicts):
        for topo_id, as_topo in topo_dicts.items():
            base = topo_id.base_dir(self.args.output_dir)
            write_file(os.path.join(base, 'keys', 'master0.key'),
                       base64.b64encode(os.urandom(16)).decode())
            write_file(os.path.join(base, 'keys', 'master1.key'),
                       base64.b64encode(os.urandom(16)).decode())

    def _copy_files(self, topo_dicts):
        cp = local['cp']
        # Copy the certs and key dir for all elements.
        for topo_id, as_topo in topo_dicts.items():
            base = local.path(self.args.output_dir)
            crypto_dir = base / topo_id.ISD() / topo_id.AS_file()
            as_dir = local.path(topo_id.base_dir(self.args.output_dir))
            cp('-r', crypto_dir / 'crypto', as_dir / 'crypto')
            cp('-r', crypto_dir / 'certs', as_dir / 'certs')
            cp(base // '*/trcs/*.trc', as_dir / 'certs')
        # Copy the customers dir for all certificate servers.
        for topo_id, as_topo in topo_dicts.items():
            as_dir = local.path(topo_id.base_dir(self.args.output_dir))
            custom_dir = as_dir / 'customers'
            if not custom_dir.exists():
                continue
            for elem in as_topo["ControlService"]:
                cp('-r', as_dir / 'customers', as_dir / elem / 'customers')
