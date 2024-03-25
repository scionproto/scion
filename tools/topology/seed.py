# Copyright 2024 ETH Zürich, Lorin Urbantat
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
import subprocess
from ipaddress import IPv4Network

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

class CrossConnectNetAssigner:
    def __init__(self):
        self.subnet_iter = IPv4Network("10.3.0.0/16").subnets(new_prefix=29)
        self.xc_nets = {}

    def next_addr(self, net):
        if net not in self.xc_nets:
            hosts = next(self.subnet_iter).hosts()
            next(hosts) # Skip first IP (reserved for Docker)
            self.xc_nets[net] = hosts
        return "{}/29".format(next(self.xc_nets[net]))


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
routing = ScionRouting()
scion_isd = ScionIsd()
scion = Scion()

"""

    def generate(self):
    
        self.out_file += self._create_ISD()

        self.out_file += self._create_AS()


        self.out_file += f"""
# Rendering
emu.addLayer(base)
emu.addLayer(routing)
emu.addLayer(scion_isd)
emu.addLayer(scion)

emu.render()

# Compilation
emu.compile(Docker(internetMapEnabled=True), './{self.args.output_dir}/seed-compiled')
"""
        # write seed file
        write_file(os.path.join(self.args.output_dir, SEED_CONF), self.out_file)
        # generate simulation from seed file
        print("\n\nRunning Seed Generation\n\n")
        subprocess.run(["python", self.args.output_dir + "/" + SEED_CONF])
    
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

        xc_nets = CrossConnectNetAssigner()

        # keep track of links
        links = []
        
        code = "# Ases \n"

        for As in self.args.topo_dicts:
            as_num = As.AS().split(':')[2]
            isd_num = As.ISD()[3]
            is_core = True if (self.args.topo_dicts[As]["attributes"] and self.args.topo_dicts[As]["attributes"][0] == 'core') else False
            # create basic As config
            code += f"""
# AS-{as_num}
as{as_num} = base.createAutonomousSystem({as_num})
scion_isd.addIsdAs({isd_num},{as_num},is_core={is_core})
"""         
            # set cert Issuer if not core AS
            if not is_core:
                issuer_isd_num = self.args.topo_dicts[As]["cert_issuer"].split(':')[-1]
                code += f"scion_isd.setCertIssuer(({isd_num},{as_num}),issuer={issuer_isd_num})\n"

            # create internal network
            code += f"as{as_num}.createNetwork('net0')\n"
            # create control Service
            code += f"as{as_num}.createControlService('cs_1').joinNetwork('net0')\n"
            # create routers
            border_routers = self.args.topo_dicts[As]["border_routers"]

            for router in border_routers:
                br_name = "br" + router.split('-')[2]
                code += f"as_{as_num}_{br_name} = as{as_num}.createRouter('{br_name}').joinNetwork('net0')\n"
                # create cross connect
                interfaces = border_routers[router]['interfaces']
                for interface in interfaces:
                    peer_as = interfaces[interface]['isd_as'].split(':')[2]
                    link_type = interfaces[interface]['link_to']
                    remote_addr = interfaces[interface]['underlay']['remote']
                    # find other AS bridge name
                    other_br_name = self.__other_bridge_name(remote_addr)
                    # generate new address because addresses form Topo-Tool dont work with seed
                    # always order as_nums to have unique name for both sides
                    if (as_num < peer_as):
                        addr = xc_nets.next_addr(f"{as_num}_{peer_as}")
                    else :
                        addr = xc_nets.next_addr(f"{peer_as}_{as_num}")
                    # generate code
                    code += f"as_{as_num}_{br_name}.crossConnect({peer_as},'{other_br_name}','{addr}')\n"
                    if ((isd_num,peer_as,as_num,link_type) not in links and link_type != "parent"):
                        links.append((isd_num,as_num,peer_as,link_type))

        code += "\n\n"

        # create inter-AS links
        code += "# Inter-AS routing\n"
        code += self.__inter_AS_links(links)
        code += "\n\n"

        return code

    def __other_bridge_name(self,address):
        for As in self.args.topo_dicts:
            as_num = As.AS().split(':')[2]
            border_routers = self.args.topo_dicts[As]["border_routers"]
            for router in border_routers:
                br_name = "br" + router.split('-')[2]
                interfaces = border_routers[router]['interfaces']
                for interface in interfaces:
                    addr = interfaces[interface]['underlay']['public']
                    if address == addr:
                        return f"br{router.split('-')[2]}"
        return None

    def __inter_AS_links(self, links):
        code = ""
        # find link pairs
        for link in links:
            isd1 = link[0]
            as1 = link[1]
            as2 = link[2]
            link_type = link[3]
            if link_type == "child":
                link_type = "Transit"
            code += f"scion.addXcLink(({isd1}, {as1}), ({isd1}, {as2}), ScLinkType.{link_type})\n"
        return code 