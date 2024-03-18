x# Copyright 2024 ETH Zürich, Lorin Urbantat
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

from typing import Mapping
import os

from topology.util import write_file
from topology.common import (
    ArgsTopoDicts
)
from topology.net import NetworkDescription, IPNetwork


SEED_CONF = "scion-seed.py"


class SeedGenArgs(ArgsTopoDicts):
    def __init__(self, args, topo_dicts,
                 networks: Mapping[IPNetwork, NetworkDescription]):
        """
        :param object args: Contains the passed command line arguments as named attributes.
        :param dict topo_dicts: The generated topo dicts from TopoGenerator.
        :param dict networks: The generated network descriptions from NetworkGenerator.
        """
        super().__init__(args, topo_dicts)
        self.networks = networks

class SeedGenerator(object):
    def __init__(self, args):
        """
        :param SeedGenArgs args: Contains the passed command line arguments and topo dicts.
        """
        self.args = args
        self.out_file = """
#!/usr/bin/env python3

from seedemu.compiler import Docker
from seedemu.core import Emulator
from seedemu.layers import ScionBase, ScionRouting, ScionIsd, Scion
from seedemu.layers.Scion import LinkType as ScLinkType

# Initialize
emu = Emulator()
base = ScionBase()
routing = ScionRouting()t
scion_isd = ScionIsd()
scion = Scion()

"""

    def generate(self):
    
        self.out_file += self._create_ISD()

        self.out_file += self._create_AS()

        self.out_file += """
# Rendering
emu.addLayer(base)
emu.addLayer(routing)
emu.addLayer(scion_isd)
emu.addLayer(scion)

emu.render()

# Compilation
emu.compile(Docker(), './output')
"""

        write_file(os.path.join(self.args.output_dir, SEED_CONF), self.out_file)
    
    def _isd_Set(self):
        isds = set()
        for As in self.args.topo_dicts:
            # get Id of every ISD
            isd = As.ISD()[3]
            isds.add(isd)
        return isds


    def _create_ISD(self):
        code = "# Create ISDs\n"
        # get set of ISDs
        isds = self._isd_Set()
        # write code for each ISD
        for isd in isds:
            code += f"base.createIsolationDomain({isd})\n"

        code += "\n\n"
        return code

    def _create_AS(self):
        code = "# Ases \n"
        for As in self.args.topo_dicts:
            as_num = As.AS().split(':')[2]
            isd_num = As.ISD()[3]
            is_core = True if (self.args.topo_dicts[As]["attributes"] and self.args.topo_dicts[As]["attributes"][0] == 'core') else False
            print(is_core)
            code += f"""
# AS-{as_num}
as{as_num} = base.createAutonomousSystem({as_num})
scion_isd().addIsdAs({isd_num},{as_num},is_core={is_core})
"""

        return code

    def _create_links(self):
        pass # TODO: implement _create_links function


