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
import os
import random
from collections import defaultdict

# External packages
import yaml
from external.ipaddress import ip_address

# SCION
from lib.defines import (
    AS_LIST_FILE,
    DEFAULT_MTU,
    IFIDS_FILE,
    OVERLAY_FILE,
    SCION_MIN_MTU,
    SCION_ROUTER_PORT,
    TOPO_FILE,
)
from lib.topology import Topology
from lib.types import LinkType
from lib.util import write_file
from topology.common import _srv_iter, TopoID, SCION_SERVICE_NAMES
from topology.net import AddressProxy

DEFAULT_LINK_BW = 1000

DEFAULT_BEACON_SERVERS = 1
DEFAULT_GRACE_PERIOD = 18000
DEFAULT_CERTIFICATE_SERVERS = 1
DEFAULT_PATH_SERVERS = 1
DEFAULT_DISCOVERY_SERVERS = 1

ZOOKEEPER_ADDR = "172.18.0.1"


class TopoGenerator(object):
    def __init__(self, topo_config, out_dir, subnet_gen, prvnet_gen, zk_config,
                 default_mtu, gen_bind_addr, docker, ipv6, cs, ps, ds, port_gen):
        self.topo_config = topo_config
        self.out_dir = out_dir
        self.subnet_gen = subnet_gen
        self.prvnet_gen = prvnet_gen
        self.zk_config = zk_config
        self.default_mtu = default_mtu
        self.gen_bind_addr = gen_bind_addr
        self.docker = docker
        self.topo_dicts = {}
        self.hosts = []
        self.zookeepers = defaultdict(dict)
        self.virt_addrs = set()
        self.as_list = defaultdict(list)
        self.links = defaultdict(list)
        self.ifid_map = {}
        if ipv6:
            self.overlay = "UDP/IPv6"
            self.addr_type = "IPv6"
        else:
            self.overlay = "UDP/IPv4"
            self.addr_type = "IPv4"
        self.cs = cs
        self.ps = ps
        self.ds = ds
        self.port_gen = port_gen

    def _reg_addr(self, topo_id, elem_id):
        subnet = self.subnet_gen.register(topo_id)
        return subnet.register(elem_id)

    def _reg_bind_addr(self, topo_id, elem_id):
        prvnet = self.prvnet_gen.register(topo_id)
        return prvnet.register(elem_id)

    def _reg_link_addrs(self, local_br, remote_br, local_ifid, remote_ifid):
        link_name = str(sorted((local_br, remote_br)))
        link_name += str(sorted((local_ifid, remote_ifid)))
        subnet = self.subnet_gen.register(link_name)
        return subnet.register(local_br), subnet.register(remote_br)

    def _iterate(self, f):
        for isd_as, as_conf in self.topo_config["ASes"].items():
            f(TopoID(isd_as), as_conf)

    def generate(self):
        self._read_links()
        self._iterate(self._generate_as_topo)
        self._iterate(self._generate_as_list)
        networks = self.subnet_gen.alloc_subnets()
        prv_networks = self.prvnet_gen.alloc_subnets()
        self._write_as_topos()
        self._write_as_list()
        self._write_ifids()
        self._write_overlay()
        return self.topo_dicts, self.zookeepers, networks, prv_networks

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
        ifid = if_ids[ep].new()
        return br, ifid

    def _read_links(self):
        assigned_br_id = {}
        br_ids = defaultdict(int)
        if_ids = defaultdict(lambda: IFIDGenerator())
        if not self.topo_config.get("links", None):
            return
        for attrs in self.topo_config["links"]:
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
        mtu = as_conf.get('mtu', self.default_mtu)
        assert mtu >= SCION_MIN_MTU, mtu
        self.topo_dicts[topo_id] = {
            'Core': as_conf.get('core', False), 'ISD_AS': str(topo_id),
            'ZookeeperService': {}, 'MTU': mtu, 'Overlay': self.overlay
        }
        for i in SCION_SERVICE_NAMES:
            self.topo_dicts[topo_id][i] = {}
        self._gen_srv_entries(topo_id, as_conf)
        self._gen_br_entries(topo_id)
        self._gen_zk_entries(topo_id, as_conf)

    def _gen_srv_entries(self, topo_id, as_conf):
        for conf_key, def_num, nick, topo_key in (
            ("beacon_servers", DEFAULT_BEACON_SERVERS, "bs", "BeaconService"),
            ("certificate_servers", DEFAULT_CERTIFICATE_SERVERS, "cs",
             "CertificateService"),
            ("path_servers", DEFAULT_PATH_SERVERS, "ps", "PathService"),
            ("discovery_servers", DEFAULT_DISCOVERY_SERVERS, "ds",
             "DiscoveryService"),
        ):
            self._gen_srv_entry(
                topo_id, as_conf, conf_key, def_num, nick, topo_key)

    def _gen_srv_entry(self, topo_id, as_conf, conf_key, def_num, nick,
                       topo_key):
        count = as_conf.get(conf_key, def_num)
        # only a single Go-PS/Go-CS per AS is currently supported
        if ((conf_key == "path_servers" and self.ps == "go") or
           (conf_key == "certificate_servers" and self.cs == "go")):
            count = 1
        if conf_key == "discovery_servers" and not self.ds:
            count = 0
        for i in range(1, count + 1):
            elem_id = "%s%s-%s" % (nick, topo_id.file_fmt(), i)
            d = {
                'Addrs': {
                    self.addr_type: {
                        'Public': {
                            'Addr': self._reg_addr(topo_id, elem_id),
                            'L4Port': self.port_gen.register(elem_id),
                        }
                    }
                }
            }
            if self.gen_bind_addr:
                d['Addrs'][self.addr_type]['Bind'] = {
                    'Addr': self._reg_bind_addr(topo_id, elem_id),
                    'L4Port': self.port_gen.register(elem_id),
                }
            self.topo_dicts[topo_id][topo_key][elem_id] = d

    def _gen_br_entries(self, topo_id):
        for (linkto, remote, attrs, l_br, r_br, l_ifid, r_ifid) in self.links[topo_id]:
            self._gen_br_entry(topo_id, l_ifid, remote, r_ifid, linkto, attrs, l_br, r_br)

    def _gen_br_entry(self, local, l_ifid, remote, r_ifid, remote_type, attrs,
                      local_br, remote_br):
        public_addr, remote_addr = self._reg_link_addrs(local_br, remote_br, l_ifid, r_ifid)
        int_addr = self._reg_addr(local, local_br)

        if self.topo_dicts[local]["BorderRouters"].get(local_br) is None:
            self.topo_dicts[local]["BorderRouters"][local_br] = {
                'CtrlAddr': {
                    self.addr_type: {
                        'Public': {
                            'Addr': int_addr,
                            'L4Port': self.port_gen.register(local_br),
                        }
                    }
                },
                'InternalAddrs': {
                    self.addr_type: {
                        'PublicOverlay': {
                            'Addr': int_addr,
                            'OverlayPort': self.port_gen.register(local_br),
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
            'Overlay': self.overlay,
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

    def _gen_zk_entries(self, topo_id, as_conf):
        zk_conf = {}
        if "zookeepers" in self.topo_config.get("defaults", {}):
            zk_conf = self.topo_config["defaults"]["zookeepers"]
        if self.docker:
            zk_conf[1] = {'addr': ZOOKEEPER_ADDR}
        for key, val in zk_conf.items():
            self._gen_zk_entry(topo_id, key, val)

    def _gen_zk_entry(self, topo_id, zk_id, zk_conf):
        zk = ZKTopo(zk_conf, self.zk_config)
        addr = str(zk.addr)
        self.topo_dicts[topo_id]["ZookeeperService"][zk_id] = {
            'Addr': addr,
            'L4Port': zk.clientPort
        }

    def _generate_as_list(self, topo_id, as_conf):
        if as_conf.get('core', False):
            key = "Core"
        else:
            key = "Non-core"
        self.as_list[key].append(str(topo_id))

    def _write_as_topos(self):
        for topo_id, as_topo, base in _srv_iter(
                self.topo_dicts, self.out_dir, common=True):
            path = os.path.join(base, TOPO_FILE)
            contents_json = json.dumps(self.topo_dicts[topo_id],
                                       default=_json_default, indent=2)
            write_file(path, contents_json + '\n')
            # Test if topo file parses cleanly
            Topology.from_file(path)

    def _write_as_list(self):
        list_path = os.path.join(self.out_dir, AS_LIST_FILE)
        write_file(list_path, yaml.dump(dict(self.as_list)))

    def _write_ifids(self):
        list_path = os.path.join(self.out_dir, IFIDS_FILE)
        write_file(list_path, yaml.dump(self.ifid_map,
                                        default_flow_style=False))

    def _write_overlay(self):
        file_path = os.path.join(self.out_dir, OVERLAY_FILE)
        write_file(file_path, self.overlay + '\n')


class LinkEP(TopoID):
    def __init__(self, raw):
        self._brid = None
        isd_as = raw
        parts = raw.split("-")
        if len(parts) == 3:
            self._brid = parts[2]
            isd_as = "%s-%s" % (parts[0], parts[1])
        super().__init__(isd_as)

    def br_name(self):
        if self._brid is not None:
            return "%s-%s" % (self.file_fmt(), self._brid)
        return None


class ZKTopo(object):
    def __init__(self, topo_config, zk_config):
        self.addr = None
        self.topo_config = topo_config
        self.zk_config = zk_config
        self.addr = ip_address(self.topo_config["addr"])
        self.clientPort = self._get_def("clientPort")

    def _get_def(self, key):
        return self.topo_config.get(key, self.zk_config["Default"][key])


class IFIDGenerator(object):
    """Generates unique interface IDs"""
    def __init__(self):
        self._ifids = set()

    def new(self):
        while True:
            ifid = random.randrange(10, 100)
            if ifid in self._ifids:
                continue
            self._ifids.add(ifid)
            return ifid


def _json_default(o):
    if isinstance(o, AddressProxy):
        return str(o.ip)
    raise TypeError
