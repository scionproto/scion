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
:mod:`topo` --- SCION topology topo generator
=============================================
"""
# Stdlib
import json
import logging
import os
import random
import sys
from collections import defaultdict

# External packages
import yaml

# SCION
from lib.defines import (
    AS_LIST_FILE,
    DEFAULT_MTU,
    IFIDS_FILE,
    SCION_MIN_MTU,
    SCION_ROUTER_PORT,
    TOPO_FILE,
)
from lib.types import LinkType
from lib.util import write_file
from topology.common import (
    ArgsBase,
    json_default,
    SCION_SERVICE_NAMES,
    srv_iter,
    TopoID
)
from topology.net import PortGenerator

DEFAULT_LINK_BW = 1000

DEFAULT_BEACON_SERVERS = 1
DEFAULT_GRACE_PERIOD = 18000
DEFAULT_CONTROL_SERVERS = 1
DEFAULT_COLIBRI_SERVERS = 1

UNDERLAY_4 = 'UDP/IPv4'
UNDERLAY_6 = 'UDP/IPv6'
DEFAULT_UNDERLAY = UNDERLAY_4
ADDR_TYPE_4 = 'IPv4'
ADDR_TYPE_6 = 'IPv6'


class TopoGenArgs(ArgsBase):
    def __init__(self, args, topo_config, subnet_gen4, subnet_gen6, default_mtu):
        """
        :param ArgsBase args: Contains the passed command line arguments.
        :param dict topo_config: The parsed topology config.
        :param SubnetGenerator subnet_gen4: The default network generator for IPv4.
        :param SubnetGenerator subnet_gen6: The default network generator for IPv6.
        :param dict default_mtu: The default mtu.
        """
        super().__init__(args)
        self.topo_config_dict = topo_config
        self.subnet_gen = {
            ADDR_TYPE_4: subnet_gen4,
            ADDR_TYPE_6: subnet_gen6,
        }
        self.default_mtu = default_mtu
        self.port_gen = PortGenerator()


class TopoGenerator(object):
    def __init__(self, args):
        """
        :param TopoGenArgs args: Contains the passed command line arguments.
        """
        self.args = args
        self.topo_dicts = {}
        self.hosts = []
        self.virt_addrs = set()
        self.as_list = defaultdict(list)
        self.links = defaultdict(list)
        self.ifid_map = {}

    def _reg_addr(self, topo_id, elem_id, addr_type):
        subnet = self.args.subnet_gen[addr_type].register(topo_id)
        return subnet.register(elem_id)

    def _reg_link_addrs(self, local_br, remote_br, local_ifid, remote_ifid, addr_type):
        link_name = str(sorted((local_br, remote_br)))
        link_name += str(sorted((local_ifid, remote_ifid)))
        subnet = self.args.subnet_gen[addr_type].register(link_name)
        return subnet.register(local_br), subnet.register(remote_br)

    def _iterate(self, f):
        for isd_as, as_conf in self.args.topo_config_dict["ASes"].items():
            f(TopoID(isd_as), as_conf)

    def generate(self):
        self._read_links()
        self._iterate(self._generate_as_topo)
        self._iterate(self._generate_as_list)
        if self.args.sig:
            self._iterate(self._register_sig)
        self._iterate(self._register_sciond)
        networks = {}
        for k, v in self.args.subnet_gen[ADDR_TYPE_4].alloc_subnets().items():
            networks[k] = v
        for k, v in self.args.subnet_gen[ADDR_TYPE_6].alloc_subnets().items():
            networks[k] = v
        self._write_as_topos()
        self._write_as_list()
        self._write_ifids()
        return self.topo_dicts, networks

    def _register_sig(self, topo_id, as_conf):
        addr_type = addr_type_from_underlay(as_conf.get('underlay', DEFAULT_UNDERLAY))
        self._reg_addr(topo_id, "sig" + topo_id.file_fmt(), addr_type)

    def _register_sciond(self, topo_id, as_conf):
        addr_type = addr_type_from_underlay(as_conf.get('underlay', DEFAULT_UNDERLAY))
        self._reg_addr(topo_id, "sd" + topo_id.file_fmt(), addr_type)
        # Always register the tester element. This causes the generator to create a
        # bridge in the docker topology, which SCIOND, SIG (if enabled) and
        # client applications can use to communicate.
        self._reg_addr(topo_id, "tester_" + topo_id.file_fmt(), addr_type)

    def _br_name(self, ep, assigned_br_id, br_ids, if_ids):
        br_name = ep.br_name()
        if br_name:
            # BR with multiple interfaces, reuse assigned id
            br_id = assigned_br_id.get(br_name)
            if br_id is None:
                # assign new id
                br_ids[ep] += 1
                assigned_br_id[br_name] = br_id = br_ids[ep]
        else:
            # BR with single interface
            br_ids[ep] += 1
            br_id = br_ids[ep]
        br = "br%s-%d" % (ep.file_fmt(), br_id)
        ifid = ep.ifid
        if self.args.random_ifids or not ifid:
            ifid = if_ids[ep].new()
        else:
            if_ids[ep].add(ifid)
        return br, ifid

    def _read_links(self):
        assigned_br_id = {}
        br_ids = defaultdict(int)
        if_ids = defaultdict(lambda: IFIDGenerator())
        if not self.args.topo_config_dict.get("links", None):
            return
        for attrs in self.args.topo_config_dict["links"]:
            a = LinkEP(attrs.pop("a"))
            b = LinkEP(attrs.pop("b"))
            linkto = linkto_a = linkto_b = attrs.pop("linkAtoB")
            if linkto.lower() == LinkType.CHILD:
                linkto_a = LinkType.PARENT
                linkto_b = LinkType.CHILD
            a_br, a_ifid = self._br_name(a, assigned_br_id, br_ids, if_ids)
            b_br, b_ifid = self._br_name(b, assigned_br_id, br_ids, if_ids)
            self.links[a].append((linkto_b, b, attrs, a_br, b_br, a_ifid, b_ifid))
            self.links[b].append((linkto_a, a, attrs, b_br, a_br, b_ifid, a_ifid))
            a_desc = "%s %s" % (a_br, a_ifid)
            b_desc = "%s %s" % (b_br, b_ifid)
            self.ifid_map.setdefault(str(a), {})
            self.ifid_map[str(a)][a_desc] = b_desc
            self.ifid_map.setdefault(str(b), {})
            self.ifid_map[str(b)][b_desc] = a_desc

    def _generate_as_topo(self, topo_id, as_conf):
        mtu = as_conf.get('mtu', self.args.default_mtu)
        assert mtu >= SCION_MIN_MTU, mtu
        attributes = []
        for attr in ['authoritative', 'core', 'issuing', 'voting']:
            if as_conf.get(attr, False):
                attributes.append(attr)
        self.topo_dicts[topo_id] = {
            'Attributes': attributes,
            'ISD_AS': str(topo_id),
            'MTU': mtu,
            'Overlay': as_conf.get('underlay', DEFAULT_UNDERLAY),
        }
        for i in SCION_SERVICE_NAMES:
            self.topo_dicts[topo_id][i] = {}
        self._gen_srv_entries(topo_id, as_conf)
        self._gen_br_entries(topo_id, as_conf)
        if self.args.sig:
            self.topo_dicts[topo_id]['SIG'] = {}
            self._gen_sig_entries(topo_id, as_conf)

    def _gen_srv_entries(self, topo_id, as_conf):
        srvs = [("control_servers", DEFAULT_CONTROL_SERVERS, "cs", "ControlService")]
        if self.args.colibri:
            srvs.append(("colibri_servers", DEFAULT_COLIBRI_SERVERS, "co", "ColibriService"))
        for conf_key, def_num, nick, topo_key in srvs:
            self._gen_srv_entry(topo_id, as_conf, conf_key, def_num, nick, topo_key)

    def _gen_srv_entry(self, topo_id, as_conf, conf_key, def_num, nick,
                       topo_key, uses_dispatcher=True):
        addr_type = addr_type_from_underlay(as_conf.get('underlay', DEFAULT_UNDERLAY))
        count = self._srv_count(as_conf, conf_key, def_num)
        for i in range(1, count + 1):
            elem_id = "%s%s-%s" % (nick, topo_id.file_fmt(), i)

            reg_id = elem_id

            port = self._default_ctrl_port(nick)
            if not self.args.docker:
                port = self.args.port_gen.register(elem_id)

            d = {
                'Addrs': {
                    addr_type: {
                        'Public': {
                            'Addr': self._reg_addr(topo_id, reg_id, addr_type),
                            'L4Port': port,
                        }
                    }
                }
            }
            self.topo_dicts[topo_id][topo_key][elem_id] = d

    def _default_ctrl_port(self, nick):
        if nick == "cs":
            return 30252
        if nick == "co":
            return 30257
        print('Invalid nick: %s' % nick)
        sys.exit(1)

    def _srv_count(self, as_conf, conf_key, def_num):
        count = as_conf.get(conf_key, def_num)
        if conf_key == "control_servers":
            count = 1
        return count

    def _gen_br_entries(self, topo_id, as_conf):
        addr_type = addr_type_from_underlay(as_conf.get('underlay', DEFAULT_UNDERLAY))
        for (linkto, remote, attrs, l_br, r_br, l_ifid, r_ifid) in self.links[topo_id]:
            self._gen_br_entry(topo_id, l_ifid, remote, r_ifid,
                               linkto, attrs, l_br, r_br, addr_type)

    def _gen_br_entry(self, local, l_ifid, remote, r_ifid, remote_type, attrs,
                      local_br, remote_br, addr_type):
        link_addr_type = addr_type_from_underlay(attrs.get('underlay', DEFAULT_UNDERLAY))
        public_addr, remote_addr = self._reg_link_addrs(local_br, remote_br, l_ifid,
                                                        r_ifid, link_addr_type)

        ctrl_addr = int_addr = self._reg_addr(local, local_br + "_ctrl", addr_type)
        if self.args.docker:
            int_addr = self._reg_addr(local, local_br + "_internal", addr_type)

        if self.topo_dicts[local]["BorderRouters"].get(local_br) is None:
            ctrl_port = 30242
            intl_port = 30042
            if not self.args.docker:
                ctrl_port = self.args.port_gen.register(local_br + "_ctrl")
                intl_port = self.args.port_gen.register(local_br + "_internal")

            self.topo_dicts[local]["BorderRouters"][local_br] = {
                'CtrlAddr': {
                    addr_type: {
                        'Public': {
                            'Addr': ctrl_addr,
                            'L4Port': ctrl_port,
                        }
                    }
                },
                'InternalAddrs': {
                    addr_type: {
                        'PublicOverlay': {
                            'Addr': int_addr,
                            'OverlayPort': intl_port,
                        }
                    }
                },
                'Interfaces': {
                    l_ifid: self._gen_br_intf(remote, public_addr, remote_addr, attrs, remote_type)
                }
            }
        else:
            # There is already a BR entry, add interface
            intf = self._gen_br_intf(remote, public_addr, remote_addr, attrs, remote_type)
            self.topo_dicts[local]["BorderRouters"][local_br]['Interfaces'][l_ifid] = intf

    def _gen_br_intf(self, remote, public_addr, remote_addr, attrs, remote_type):
        return {
            'Overlay': attrs.get('underlay', DEFAULT_UNDERLAY),
            'PublicOverlay': {
                'Addr': public_addr,
                'OverlayPort': SCION_ROUTER_PORT
            },
            'RemoteOverlay': {
                'Addr': remote_addr,
                'OverlayPort': SCION_ROUTER_PORT
            },
            'Bandwidth': attrs.get('bw', DEFAULT_LINK_BW),
            'ISD_AS': str(remote),
            'LinkTo': LinkType.to_str(remote_type.lower()),
            'MTU': attrs.get('mtu', DEFAULT_MTU)
        }

    def _gen_sig_entries(self, topo_id, as_conf):
        addr_type = addr_type_from_underlay(DEFAULT_UNDERLAY)
        elem_id = "sig" + topo_id.file_fmt()
        reg_id = "sig" + topo_id.file_fmt()
        port = 30256
        if not self.args.docker:
            port = self.args.port_gen.register(elem_id)
        d = {
            'Addrs': {
                addr_type: {
                    'Public': {
                        'Addr': self._reg_addr(topo_id, reg_id, addr_type),
                        'L4Port': port,
                    }
                }
            }
        }
        self.topo_dicts[topo_id]['SIG'][elem_id] = d

    def _generate_as_list(self, topo_id, as_conf):
        if as_conf.get('core', False):
            key = "Core"
        else:
            key = "Non-core"
        self.as_list[key].append(str(topo_id))

    def _write_as_topos(self):
        for topo_id, as_topo, base in srv_iter(
                self.topo_dicts, self.args.output_dir, common=True):
            path = os.path.join(base, TOPO_FILE)
            contents_json = json.dumps(self.topo_dicts[topo_id],
                                       default=json_default, indent=2)
            write_file(path, contents_json + '\n')

    def _write_as_list(self):
        list_path = os.path.join(self.args.output_dir, AS_LIST_FILE)
        write_file(list_path, yaml.dump(dict(self.as_list)))

    def _write_ifids(self):
        list_path = os.path.join(self.args.output_dir, IFIDS_FILE)
        write_file(list_path, yaml.dump(self.ifid_map,
                                        default_flow_style=False))


class LinkEP(TopoID):
    def __init__(self, raw):
        self._brid = None
        self.ifid = None
        isd_as = raw
        parts = raw.split('#')
        if len(parts) == 2:
            self.ifid = int(parts[1])
            isd_as = parts[0]
        parts = isd_as.split("-")
        if len(parts) == 3:
            self._brid = parts[2]
            isd_as = "%s-%s" % (parts[0], parts[1])
        super().__init__(isd_as)

    def br_name(self):
        if self._brid is not None:
            return "%s-%s" % (self.file_fmt(), self._brid)
        return None


class IFIDGenerator(object):
    """Generates unique interface IDs"""

    def __init__(self):
        self._ifids = set()

    def new(self):
        while True:
            ifid = random.randrange(1, 4096)
            if ifid in self._ifids:
                continue
            self.add(ifid)
            return ifid

    def add(self, ifid):
        if ifid in self._ifids:
            logging.critical("IFID %d already exists!" % ifid)
            exit(1)
        if ifid < 1 or ifid > 4095:
            logging.critical("IFID %d is invalid!" % ifid)
            exit(1)
        self._ifids.add(ifid)


def addr_type_from_underlay(underlay: str) -> str:
    return underlay.split('/')[1]
