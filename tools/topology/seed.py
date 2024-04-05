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
import yaml

SEED_CONF = "scion-seed.py"

# class to manage seed arguments
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


# copyright @lschulz -- https://github.com/Bruol/seed-emulator/blob/master/examples/scion/S05-scion-internet/scion-internet.py
# class to generate IP addresses for cross connect links
class CrossConnectNetAssigner:
    def __init__(self,parentNet):
        self.subnet_iter = IPv4Network(parentNet).subnets(new_prefix=29)
        self.xc_nets = {}

    def next_addr(self, net):
        if net not in self.xc_nets:
            hosts = next(self.subnet_iter).hosts()
            next(hosts) # Skip first IP (reserved for Docker)
            self.xc_nets[net] = hosts
        return "{}/29".format(next(self.xc_nets[net]))

class SeedGenerator(object):
    # define class variables
    _topo_file : dict
    _args : SeedGenArgs
    _out_file : str
    _links : list
    _br : dict
    _internetMapEnabled : bool=True
    _SeedCompiler : str="Docker"
    _skipIPv6Check : bool=False
    _parentNetwork : str = "10.3.0.0/16"

    def __init__(self, args):
        """
        :param SeedGenArgs args: Contains the passed command line arguments and topo dicts.

        Generates a seed file for the SCION topology.
        """
        self._args = args

        self._parseFeatures()
        
        with open(args.topo_config,"r") as f:
            self._topo_file = yaml.load(f, Loader=yaml.SafeLoader)

    def _parseFeatures(self):
        if "SeedInternetMapDisable" in self._args.features:
            self._internetMapEnabled = False
        if "SeedCompilerGraphviz" in self._args.features:
            self._SeedCompiler = "Graphviz"
        if "SeedSkipIPv6Check" in self._args.features:
            self._skipIPv6Check = True
        if self._args.network:
            self._parentNetwork = self._args.network
        
        
        

    def generate(self):
        """
        generate function called by ./config.py to generate seed file
        """

        # Seed does not support IPv6 thus throw error if IPv6 is used
        if not self._skipIPv6Check:
            self._check_IPv6()
        
        # write header of seed file
        self._out_file = """

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

        # build appropriate link data structure
        self._links = self._parse_links()

        self._parse_borderRouter_interfaces()
        
        self._generate_addresses()

        self._out_file += self._create_ISD()

        self._out_file += self._create_AS()

        self._out_file += self._create_Routing()

        self._out_file += f"""
# Rendering
emu.addLayer(base)
emu.addLayer(routing)
emu.addLayer(scion_isd)
emu.addLayer(scion)

emu.render()

# Compilation
emu.compile({self._SeedCompiler}(internetMapEnabled={self._internetMapEnabled}), './{self._args.output_dir}/seed-compiled')
"""
        # write seed file
        write_file(os.path.join(self._args.output_dir, SEED_CONF), self._out_file)
        # generate simulation from seed file
        print("\n\nRunning Seed Generation\n\n")
        subprocess.run(["python", self._args.output_dir + "/" + SEED_CONF])
    
    def _isd_Set(self):
        """
        Generate a set of ISDs from the topo file
        """
        isds = set()
        for As in self._topo_file["ASes"]:
            # get Id of every ISD
            isd = As.split('-')[0]
            isds.add(isd)
        return isds

    def _create_ISD(self):
        """
        Generate code for creating ISDs
        """
        code = "# Create ISDs\n"
        # get set of ISDs
        isds = self._isd_Set()
        # write code for each ISD
        for isd in isds:
            code += f"base.createIsolationDomain({isd})\n"

        code += "\n\n"
        return code

    def _check_IPv6(self):
        """
        Check if any network is IPv6
        """
        for network in self._args.networks:
            if network._version == 6:
                raise Exception("Seed does not support IPv6. Please use IPv4 only. If you want to try anyway use the feature flag SeedSkipIPv6Check.")

    def _parse_AS_properties(self, As):
        """
        Read AS properties from topo file
        """
        as_num = As.split(':')[2]
        isd_num = As.split('-')[0]
        
        # handle optional properties
        as_dict = self._topo_file["ASes"][As]
        
        is_core = as_dict['core'] if 'core' in as_dict else False
        cert_issuer = as_dict['cert_issuer'].split(':')[2] if 'cert_issuer' in as_dict else None
        as_int_bw = as_dict['bandwidth'] if 'bandwidth' in as_dict else 0
        as_int_lat = as_dict['latency'] if 'latency' in as_dict else 0
        as_int_drop = as_dict['drop'] if 'drop' in as_dict else 0
        as_int_mtu = as_dict['mtu'] if 'mtu' in as_dict else None
        as_note = as_dict['note'] if 'note' in as_dict else None

        return as_num, isd_num, is_core, cert_issuer, as_int_bw, as_int_lat, as_int_drop, as_int_mtu, as_note

    def _read_link_properties(self, link):
        """
        Read link properties from topo file
        """
        a = link['a']
        b = link['b']
        link_type = self._convert_link_type(link['linkAtoB'])
        # read optional properties
        if "mtu" in link:
            mtu = link['mtu']
        else:
            mtu = None

        if "bandwidth" in link:
            bandwidth = link['bandwidth']
        else:
            bandwidth = 0 # seed ignores value 0 

        if "latency" in link:
            latency = link['latency']
        else:
            latency = 0 # seed ignores value 0
        
        if "drop" in link:
            drop = link['drop']
        else:
            drop = 0 # seed ignores value 0
        
        return a, b, link_type, mtu, bandwidth, latency, drop

    def _convert_link_type(self, link_type):
        """
        Convert link type from topo file to seed format
        """
        if link_type == "CHILD":
            return "ScLinkType.Transit"
        elif link_type == "PEER":
            return "ScLinkType.Peer"
        elif link_type == "CORE":
            return "ScLinkType.Core"
        else:
            raise Exception(f"Link type {link_type} not supported by Seed")

    def _parse_link_party(self, party):
        """
        Parse link party from topo file
        """
        isd_num = party.split('-')[0]
        as_num = party.split(':')[2]
        if "-" in as_num:
            br_if = as_num.split('-')[1]
            as_num = as_num.split('-')[0]
        else:
            br_if = as_num.split('#')[1]
            as_num = as_num.split('#')[0]
        return isd_num, as_num, br_if

    def _parse_links(self):
        """
        Parse links from topo file
        """
        links = []
        for link in self._topo_file["links"]:
            (a,b,link_type, mtu, bandwidth, latency, drop) = self._read_link_properties(link)
            (a_isd, a_as, a_br_if) = self._parse_link_party(a)
            (b_isd, b_as, b_br_if) = self._parse_link_party(b)

            data = {
                "a": (a_isd, a_as, a_br_if),
                "b": (b_isd, b_as, b_br_if),
                "link_type": link_type,
                "mtu": mtu,
                "bandwidth": bandwidth,
                "latency": latency,
                "drop": drop
            }

            links.append(data)
        return links

    def _parse_interface(self, br_if, i, ia, a_b):
        """
        :param br_if: bridge interface identifier (format A#1 or 1)
        :param i: link index
        :param ia: ISD_AS identifier

        Parse bridge interface and update bridges data structure
        """
        # create set of bridges for per AS
        if "#" in br_if:
            br_id = br_if.split('#')[0]
            # add bridge to list if not already in list 
            if (br_id not in self._br[ia]):
                self._br[ia].append(br_id)
        else:
            # if bridge does not have an ID add new ID by prepending 'A'
            last_id = "" if not self._br[ia] else self._br[ia][-1]
            new_id = "A"+last_id
            self._br[ia].append(new_id)
            # also update link data structure with new ID
            isd = ia.split('_')[0]
            as_num = ia.split('_')[1]
            self._links[i][a_b] = (isd,as_num,new_id+"#"+br_if)
            
    def _parse_borderRouter_interfaces(self):
        """
        generate bridge_names from links
        """
        
        self._br = {}

        # initialize borderRouter datastructure by creating an empty list of BorderRouters for each AS
        for As in self._topo_file["ASes"]:
            isd_num = As.split('-')[0]
            as_num = As.split(':')[2]
            ia = f"{isd_num}_{as_num}"
            self._br[ia] = []

        # parse interfaces for each link
        for i in range(0,len(self._links)): 
            link = self._links[i]

            a_br = link['a'][2]
            b_br = link['b'][2]
            a_as = link['a'][1]
            a_isd = link['a'][0]
            b_as = link['b'][1]
            b_isd = link['b'][0]

            a_ia = f"{a_isd}_{a_as}" 
            b_ia = f"{b_isd}_{b_as}"
            
            self._parse_interface(a_br, i, a_ia,"a")
            self._parse_interface(b_br, i, b_ia,"b")

        # generate border router names
        for ia in self._br:
            br_names = []
            i = 1
            for br in self._br[ia]:
                br_names.append({br: f"br{i}"})
                i += 1
            self._br[ia] = br_names
                
        
        # replace border router interface names with border router names
        for i in range(0,len(self._links)):
            link = self._links[i]
            a_br = link['a'][2]
            b_br = link['b'][2]
            a_as = link['a'][1]
            a_isd = link['a'][0]
            b_as = link['b'][1]
            b_isd = link['b'][0]

            a_br_id = a_br.split('#')[0]
            b_br_id = b_br.split('#')[0]

            for br in self._br[f"{a_isd}_{a_as}"]:
                if a_br_id in br:
                    a_br = br[a_br_id]
                    break
            
            for br in self._br[f"{b_isd}_{b_as}"]:
                if b_br_id in br:
                    b_br = br[b_br_id]
                    break
            
            self._links[i]['a'] = (a_isd, a_as, a_br)
            self._links[i]['b'] = (b_isd, b_as, b_br)

    def _generate_addresses(self):
        """
        Generate IP addresses for cross connect links
        """
        self._xc_nets = CrossConnectNetAssigner(self._parentNetwork)

        for i in range(0,len(self._links)):
            link = self._links[i]

            a = link['a']
            b = link['b']

            a_addr = self._xc_nets.next_addr((a,b))
            b_addr = self._xc_nets.next_addr((a,b))
            
            self._links[i]['a_addr'] = a_addr
            self._links[i]['b_addr'] = b_addr

    def _create_AS(self):
        """
        Generate code for creating ASes
        """
                
        code = "# Ases \n"

        for As in self._topo_file["ASes"]:
            
            (as_num, isd_num, is_core, cert_issuer, as_int_bw, as_int_lat, as_int_drop, as_int_mtu, as_note) = self._parse_AS_properties(As)

            code += f"\n# AS-{as_num}\n"
            code += f"as{as_num} = base.createAutonomousSystem({as_num})\n"
            if as_note:
                code += f"as{as_num}.setNote('{as_note}')\n"
            code += f"scion_isd.addIsdAs({isd_num},{as_num},is_core={is_core})\n"
            if cert_issuer:
                code += f"scion_isd.setCertIssuer(({isd_num},{as_num}),issuer={cert_issuer})\n"
            if as_int_mtu: # default value 0 for latency, bandwidth, packetDrop will not set these values
                code += f"as{as_num}.createNetwork('net0').setDefaultLinkProperties(latency={as_int_lat}, bandwidth={as_int_bw}, packetDrop={as_int_drop}).setMtu({as_int_mtu})\n"
            else:
                code += f"as{as_num}.createNetwork('net0').setDefaultLinkProperties(latency={as_int_lat}, bandwidth={as_int_bw}, packetDrop={as_int_drop})\n"

            code += f"as{as_num}.createControlService('cs_1').joinNetwork('net0')\n"

            # iterate through border routers
            for br in self._br[f"{isd_num}_{as_num}"]:
                br_name = next(iter(br.values()))
                code += f"as_{as_num}_{br_name} = as{as_num}.createRouter('{br_name}').joinNetwork('net0')\n"           
                # create crosslinks for each border router
                for link in self._links:
                    # check if link is connected to this AS
                    if link['a'][0] == isd_num and link['a'][1] == as_num:
                        # check if link is connected to this border router
                        if link['a'][2] == br_name:
                            b_br = link['b'][2]
                            b_as = link['b'][1]
                            a_addr = link['a_addr']
                            # get link properties
                            latency = link['latency']
                            bandwidth = link['bandwidth']
                            packetDrop = link['drop']
                            mtu = link['mtu']
                            # generate code
                            if mtu:
                                code += f"as_{as_num}_{br_name}.crossConnect({b_as},'{b_br}','{a_addr}',latency={latency},bandwidth={bandwidth},packetDrop={packetDrop},MTU={mtu})\n"
                            else:
                                code += f"as_{as_num}_{br_name}.crossConnect({b_as},'{b_br}','{a_addr}',latency={latency},bandwidth={bandwidth},packetDrop={packetDrop})\n"
                    
                    if link['b'][0] == isd_num and link['b'][1] == as_num:
                        if link['b'][2] == br_name:
                            a_br = link['a'][2]
                            a_as = link['a'][1]
                            b_addr = link['b_addr']
                            latency = link['latency']
                            bandwidth = link['bandwidth']
                            packetDrop = link['drop']
                            mtu = link['mtu']
                            if mtu:
                                code += f"as_{as_num}_{br_name}.crossConnect({a_as},'{a_br}','{b_addr}',latency={latency},bandwidth={bandwidth},packetDrop={packetDrop},MTU={mtu})\n"
                            else:
                                code += f"as_{as_num}_{br_name}.crossConnect({a_as},'{a_br}','{b_addr}',latency={latency},bandwidth={bandwidth},packetDrop={packetDrop})\n"

        return code

    def _create_Routing(self):
        """
        Generate code for creating routing
        """
        code = "\n\n# Inter-AS routing\n"
        
        for link in self._links:
            a = link['a']
            b = link['b']
            link_type = link['link_type']
            a_router = link['a'][2]
            b_router = link['b'][2]

            code += f"scion.addXcLink(({a[0]},{a[1]}),({b[0]},{b[1]}),{link_type},a_router='{a_router}',b_router='{b_router}')\n"


        return code