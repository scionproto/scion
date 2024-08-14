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

from typing import Mapping, Set, Tuple, Optional, Dict, List, Union
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


# copyright
# @lschulz -- seed-emulator/examples/scion/S05-scion-internet/scion-internet.py
# class to generate IP addresses for cross connect links


class ASNetworkAssigner:
    def __init__(self, parentNet):
        assert "/16" in parentNet, "Parent network must be a /16 network"
        self.parentNet = ".".join(parentNet.split(".")[0:2])
    
    def get_net_by_as(self, asn):
        if asn == 0:
            raise Exception("AS number 0 is invalid")
        return f"{self.parentNet}.{asn}.0/24"

class CrossConnectNetAssigner:
    def __init__(self, parentNet):
        self.subnet_iter = IPv4Network(parentNet).subnets(new_prefix=29)
        self.xc_nets = {}

    def next_addr(self, net):
        if net not in self.xc_nets:
            hosts = next(self.subnet_iter).hosts()
            next(hosts)  # Skip first IP (reserved for Docker)
            self.xc_nets[net] = hosts
        return "{}/29".format(next(self.xc_nets[net]))


class SeedGenerator(SeedGenArgs):
    # define class variables
    # dictionary containing the topo file parsed as yaml
    _topo_file: \
        Dict[str,
             Union[Dict[str, Dict[str, Union[bool, int, str]]], List[Dict[str, Union[str, int]]]]]
    _args: SeedGenArgs
    _out_file: str
    _links: List[Dict[str, Union[Tuple[str, str, str], str, int]]]  # list of parsed links
    _br: Dict[str, List[str]]
    _internetMapEnabled: bool = True
    _SeedCompiler: str = "Docker"
    _skipIPv6Check: bool = False
    _parentNetwork: str = "10.3.0.0/16"
    # dict containing mapping from ISD_AS to list of border router properties
    _brProperties: Dict[str, Dict[str, Dict]]

    def __init__(self, args):
        """
        :param SeedGenArgs args: Contains the passed command line arguments and topo dicts.

        Generates a seed file for the SCION topology.
        """
        self._args = args

        self._parseFeatures()

        with open(args.topo_config, "r") as f:
            self._topo_file = yaml.load(f, Loader=yaml.SafeLoader)

    def _parseFeatures(self):
        """
        parse cli feature flags and set class flags
        """
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
from seedemu.layers import ScionBase, ScionRouting, ScionIsd, Scion, Ospf
from seedemu.layers.Scion import LinkType as ScLinkType

# Initialize
emu = Emulator()
base = ScionBase()
routing = ScionRouting()
scion_isd = ScionIsd()
scion = Scion()
ospf = Ospf()

"""

        # build appropriate link data structure
        self._links = self._parse_links()

        self._brProperties = self._parse_borderRouterProperties()

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
emu.addLayer(ospf)

# dump seed emulation to file before rendering
emu.dump("{self._args.output_dir}/{SEED_CONF.replace('.py', '.bin')}")


emu.render()

# Compilation
emu.compile({self._SeedCompiler}(internetMapEnabled={self._internetMapEnabled}, \
internetMapClientImage="bruol0/seedemu-client"), \
'./{self._args.output_dir}/seed-compiled')
"""
        # write seed file
        write_file(os.path.join(self._args.output_dir, SEED_CONF), self._out_file)
        # generate simulation from seed file
        print("\n\nRunning Seed Generation\n\n")
        subprocess.run(["python", self._args.output_dir + "/" + SEED_CONF])

    def _isd_Set(self) -> Set[str]:
        """
        Generate a set of ISDs from the topo file
        """
        isds = set()
        for As in self._topo_file["ASes"]:
            # get Id of every ISD
            isd = As.split('-')[0]
            isds.add(isd)
        return isds

    def _create_ISD(self) -> str:
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
                raise Exception((
                    "Seed does not support IPv6. Please use IPv4 only. "
                    "If you want to try anyway use the feature flag SeedSkipIPv6Check."))

    def _parse_AS_properties(self, As: str)\
            -> Tuple[str, str, bool, Optional[str], int, int, int, Optional[int], Optional[str]]:
        """
        Read AS properties from topo file
        """
        as_num = As.split(':')[2]
        isd_num = As.split('-')[0]

        # handle optional properties
        as_dict = self._topo_file["ASes"][As]

        is_core = as_dict['core'] if 'core' in as_dict else False
        cert_issuer = as_dict['cert_issuer'].split(':')[2] if 'cert_issuer' in as_dict else None
        as_int_bw = as_dict['bw'] if 'bw' in as_dict else 0
        as_int_lat = as_dict['latency'] if 'latency' in as_dict else 0
        as_int_drop = as_dict['drop'] if 'drop' in as_dict else 0
        as_int_mtu = as_dict['mtu'] if 'mtu' in as_dict else None
        as_note = as_dict['note'] if 'note' in as_dict else None

        res = (as_num,
               isd_num,
               is_core,
               cert_issuer,
               as_int_bw,
               as_int_lat,
               as_int_drop,
               as_int_mtu,
               as_note)

        return res

    def _read_link_properties(self, link: Dict[str, Union[str, Optional[int], int]]) \
            -> Tuple[str, str, str, Optional[int], int, int, int]:
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

        if "bw" in link:
            bandwidth = link['bw']
        else:
            bandwidth = 0  # seed ignores value 0

        if "latency" in link:
            latency = link['latency']
        else:
            latency = 0  # seed ignores value 0

        if "drop" in link:
            drop = link['drop']
        else:
            drop = 0  # seed ignores value 0

        return a, b, link_type, mtu, bandwidth, latency, drop

    def _convert_link_type(self, link_type: str) -> str:
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

    def _parse_link_party(self, party: str) -> Tuple[str, str, str]:
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

    def _parse_links(self) -> List[Dict[str, Union[Tuple[str, str, str], str, int]]]:
        """
        Parse links from topo file
        """
        links = []
        for link in self._topo_file["links"]:
            (a, b, link_type, mtu, bandwidth, latency, drop) = self._read_link_properties(link)
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
            # also update link and brProperties data structure with new ID
            isd = ia.split('_')[0]
            as_num = ia.split('_')[1]
            self._links[i][a_b] = (isd, as_num, new_id+"#"+br_if)
            if ia in self._brProperties:
                if br_if in self._brProperties[ia]:
                    self._brProperties[ia][new_id+"#"+br_if] = self._brProperties[ia][br_if]
                    del self._brProperties[ia][br_if]

    def _parse_borderRouterProperties(self) -> Dict[str, Dict[str, Dict]]:
        """
        parse BorderRouter properties from topo file
        """

        brProperties = {}

        if "borderRouterProperties" not in self._topo_file:
            return brProperties

        for br in self._topo_file["borderRouterProperties"]:
            (isd, as_num, br_if) = self._parse_link_party(br)
            if f"{isd}_{as_num}" not in brProperties:
                brProperties[f"{isd}_{as_num}"] = {}
            brProperties[f"{isd}_{as_num}"][br_if] = self._topo_file["borderRouterProperties"][br]

        return brProperties

    def _parse_borderRouter_interfaces(self):
        """
        generate bridge_names from links
        """

        self._br = {}

        # initialize borderRouter datastructure
        # by creating an empty list of BorderRouters for each AS
        for As in self._topo_file["ASes"]:
            isd_num = As.split('-')[0]
            as_num = As.split(':')[2]
            ia = f"{isd_num}_{as_num}"
            self._br[ia] = []

        # parse interfaces for each link
        for i in range(0, len(self._links)):
            link = self._links[i]

            a_isd, a_as, a_br = link['a']
            b_isd, b_as, b_br = link['b']

            a_ia = f"{a_isd}_{a_as}"
            b_ia = f"{b_isd}_{b_as}"

            self._parse_interface(a_br, i, a_ia, "a")
            self._parse_interface(b_br, i, b_ia, "b")

        # generate border router names
        for ia in self._br:
            br_names = []
            i = 1
            for br in self._br[ia]:
                br_names.append({br: f"br{i}"})
                i += 1
            self._br[ia] = br_names

        # replace border router interface names with border router names in links
        for i in range(0, len(self._links)):
            link = self._links[i]

            a_isd, a_as, a_br = link['a']
            b_isd, b_as, b_br = link['b']

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

        # replace border router interface names with border router names in brProperties

        new_br_properties = {}

        for ia in self._brProperties:
            new_br_properties[ia] = {}
            for br_if in self._brProperties[ia]:
                br_id = br_if.split('#')[0]
                for br in self._br[ia]:
                    if br_id in br:
                        br_name = br[br_id]
                        new_br_properties[ia][br_name] = self._brProperties[ia][br_if]

        self._brProperties = new_br_properties

    def _generate_addresses(self):
        """
        Generate IP addresses for cross connect links
        """
        self._xc_nets = CrossConnectNetAssigner(self._parentNetwork)

        self.as_nets = ASNetworkAssigner(self._parentNetwork)

        for i in range(0, len(self._links)):
            link = self._links[i]

            a = link['a']
            b = link['b']

            a_addr = self._xc_nets.next_addr((a, b))
            b_addr = self._xc_nets.next_addr((a, b))

            self._links[i]['a_addr'] = a_addr
            self._links[i]['b_addr'] = b_addr

    def _create_AS(self) -> str:
        """
        Generate code for creating ASes
        """

        code = "# Ases \n"

        AS_template = """\
# AS-{as_num}
as{as_num} = base.createAutonomousSystem({as_num})
{set_note}
scion_isd.addIsdAs({isd_num},{as_num},is_core={is_core})
{cert_issuer}
{set_link_properties}
as{as_num}.createControlService('cs_1').joinNetwork('net0')
{border_routers}

"""

        for As in self._topo_file["ASes"]:

            (as_num,
                isd_num,
                is_core,
                cert_issuer,
                as_int_bw,
                as_int_lat,
                as_int_drop,
                as_int_mtu,
                as_note) = self._parse_AS_properties(As)

            set_note = f"as{as_num}.setNote('{as_note}')" if as_note else ""

            if cert_issuer:
                cert_issuer = f"scion_isd.setCertIssuer(({isd_num},{as_num}),issuer={cert_issuer})"
            else:
                cert_issuer = ""

            if as_int_mtu:  # default value 0 for latency, bandwidth, packetDrop will be ignored
                set_link_properties = (f"as{as_num}.createNetwork('net0', prefix=\"{self.as_nets.get_net_by_as(as_num)}\")"
                                       f".setDefaultLinkProperties("
                                       f"latency={as_int_lat},"
                                       f"bandwidth={as_int_bw},"
                                       f"packetDrop={as_int_drop}).setMtu({as_int_mtu})\n")
            else:
                set_link_properties = (f"as{as_num}.createNetwork('net0', prefix=\"{self.as_nets.get_net_by_as(as_num)}\")"
                                       f".setDefaultLinkProperties("
                                       f"latency={as_int_lat}, "
                                       f"bandwidth={as_int_bw}, "
                                       f"packetDrop={as_int_drop})\n")

            border_routers = ""

            # iterate through border routers
            for br in self._br[f"{isd_num}_{as_num}"]:
                br_name = next(iter(br.values()))
                border_routers += (f"as_{as_num}_{br_name} = as{as_num}"
                                   f".createRouter('{br_name}')"
                                   f".joinNetwork('net0')\n")

                # set border router properties
                if f"{isd_num}_{as_num}" in self._brProperties \
                        and br_name in self._brProperties[f"{isd_num}_{as_num}"]:
                    br_props = self._brProperties[f"{isd_num}_{as_num}"][br_name]

                    if "geo" in br_props:
                        lat = br_props['geo']['latitude']
                        lon = br_props['geo']['longitude']
                        addr = br_props['geo']['address']
                        border_routers += (f"as_{as_num}_{br_name}"
                                           f".setGeo(Lat={lat}, "
                                           f"Long={lon}, Address=\"\"\"{addr}\"\"\")\n")
                    if "note" in br_props:
                        border_routers += f"as_{as_num}_{br_name}.setNote('{br_props['note']}')\n"

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
                                border_routers += (f"as_{as_num}_{br_name}"
                                                   f".crossConnect({b_as},'{b_br}','{a_addr}',"
                                                   f"latency={latency},bandwidth={bandwidth},"
                                                   f"packetDrop={packetDrop},MTU={mtu})\n")
                            else:
                                border_routers += (f"as_{as_num}_{br_name}"
                                                   f".crossConnect({b_as},'{b_br}','{a_addr}',"
                                                   f"latency={latency},bandwidth={bandwidth},"
                                                   f"packetDrop={packetDrop})\n")

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
                                border_routers += (f"as_{as_num}_{br_name}"
                                                   f".crossConnect({a_as},'{a_br}','{b_addr}',"
                                                   f"latency={latency},bandwidth={bandwidth},"
                                                   f"packetDrop={packetDrop},MTU={mtu})\n")
                            else:
                                border_routers += (f"as_{as_num}_{br_name}"
                                                   f".crossConnect({a_as},'{a_br}','{b_addr}',"
                                                   f"latency={latency},bandwidth={bandwidth},"
                                                   f"packetDrop={packetDrop})\n")

            code += AS_template.format(as_num=as_num,
                                       isd_num=isd_num,
                                       is_core=is_core,
                                       cert_issuer=cert_issuer,
                                       set_note=set_note,
                                       set_link_properties=set_link_properties,
                                       border_routers=border_routers).replace("\n\n", "\n")

        return code

    def _create_Routing(self) -> str:
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

            code += (f"scion.addXcLink(({a[0]},{a[1]}),({b[0]},{b[1]}),"
                     f"{link_type},a_router='{a_router}',b_router='{b_router}')\n")
        return code
