#!/usr/bin/python3
# Copyright 2014 ETH Zurich
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
:mod:`generator` --- SCION topology generator
=============================================
"""
# Stdlib
import argparse
import base64
import configparser
import getpass
import logging
import math
import os
import random
import sys
from collections import defaultdict
from io import StringIO
from ipaddress import ip_interface, ip_network
from string import Template

# External packages
import yaml
from Crypto import Random

# SCION
from lib.config import Config
from lib.crypto.asymcrypto import (
    generate_sign_keypair,
    sign,
)
from lib.crypto.certificate import Certificate, CertificateChain, TRC
from lib.defines import (
    AS_CONF_FILE,
    AS_LIST_FILE,
    DEFAULT_MTU,
    GEN_PATH,
    LINK_CHILD,
    LINK_PARENT,
    NETWORKS_FILE,
    PATH_POLICY_FILE,
    SCION_MIN_MTU,
    SCION_ROUTER_PORT,
    TOPO_FILE,
)
from lib.path_store import PathPolicy
from lib.packet.scion_addr import ISD_AS
from lib.topology import Topology
from lib.util import (
    copy_file,
    get_cert_chain_file_path,
    get_sig_key_file_path,
    get_trc_file_path,
    load_yaml_file,
    read_file,
    write_file,
)

DEFAULT_TOPOLOGY_FILE = "topology/Default.topo"
DEFAULT_PATH_POLICY_FILE = "topology/PathPolicy.yml"
DEFAULT_ZK_CONFIG = "topology/Zookeeper.yml"
DEFAULT_ZK_LOG4J = "topology/Zookeeper.log4j"

HOSTS_FILE = 'hosts'
SUPERVISOR_CONF = 'supervisord.conf'
COMMON_DIR = 'endhost'

ZOOKEEPER_HOST_TMPFS_DIR = "/run/shm/host-zk"
ZOOKEEPER_TMPFS_DIR = "/run/shm/scion-zk"

DEFAULT_LINK_BW = 1000

DEFAULT_BEACON_SERVERS = 1
DEFAULT_CERTIFICATE_SERVERS = 1
DEFAULT_PATH_SERVERS = 1
DEFAULT_SIBRA_SERVERS = 1
INITIAL_CERT_VERSION = 0
INITIAL_TRC_VERSION = 0

DEFAULT_NETWORK = "127.0.0.0/8"
DEFAULT_MININET_NETWORK = "100.64.0.0/10"

SCION_SERVICE_NAMES = (
    "BeaconServers",
    "CertificateServers",
    "EdgeRouters",
    "PathServers",
    "SibraServers",
)


class ConfigGenerator(object):
    """
    Configuration and/or topology generator.
    """
    def __init__(self, out_dir=GEN_PATH, topo_file=DEFAULT_TOPOLOGY_FILE,
                 path_policy_file=DEFAULT_PATH_POLICY_FILE,
                 zk_config_file=DEFAULT_ZK_CONFIG, network=None,
                 use_mininet=False):
        """
        Initialize an instance of the class ConfigGenerator.

        :param string out_dir: path to the topology folder.
        :param string topo_file: path to topology config
        :param string path_policy_file: path to PathPolicy.yml
        :param string zk_config_file: path to Zookeeper.yml
        :param string network:
            Network to create subnets in, of the form x.x.x.x/y
        :param bool use_mininet: Use Mininet
        """
        self.out_dir = out_dir
        self.topo_config = load_yaml_file(topo_file)
        self.zk_config = load_yaml_file(zk_config_file)
        self.path_policy_file = path_policy_file
        self.mininet = use_mininet
        self.default_zookeepers = {}
        self.default_mtu = None
        self._read_defaults(network)

    def _read_defaults(self, network):
        """
        Configure default network and ZooKeeper setup.
        """
        defaults = self.topo_config.get("defaults", {})
        def_network = network
        if not def_network:
            def_network = defaults.get("subnet")
        if not def_network:
            if self.mininet:
                def_network = DEFAULT_MININET_NETWORK
            else:
                def_network = DEFAULT_NETWORK
        self.subnet_gen = SubnetGenerator(def_network)
        for key, val in defaults.get("zookeepers", {}).items():
            if self.mininet and val['addr'] == "127.0.0.1":
                val['addr'] = "169.254.0.1"
            self.default_zookeepers[key] = ZKTopo(
                val, self.zk_config)
        self.default_mtu = defaults.get("mtu", DEFAULT_MTU)

    def generate_all(self):
        """
        Generate all needed files.
        """
        cert_files, trc_files = self._generate_certs_trcs()
        topo_dicts, zookeepers, networks = self._generate_topology()
        self._generate_supervisor(topo_dicts, zookeepers)
        self._generate_zk_conf(zookeepers)
        self._write_trust_files(topo_dicts, cert_files)
        self._write_trust_files(topo_dicts, trc_files)
        self._write_conf_policies(topo_dicts)
        self._write_networks_conf(networks)

    def _generate_certs_trcs(self):
        certgen = CertGenerator(self.topo_config)
        return certgen.generate()

    def _generate_topology(self):
        topo_gen = TopoGenerator(
            self.topo_config, self.out_dir, self.subnet_gen, self.zk_config,
            self.default_mtu)
        return topo_gen.generate()

    def _generate_supervisor(self, topo_dicts, zookeepers):
        super_gen = SupervisorGenerator(self.out_dir, topo_dicts, zookeepers,
                                        self.zk_config, self.mininet)
        super_gen.generate()

    def _generate_zk_conf(self, zookeepers):
        zk_gen = ZKConfGenerator(self.out_dir, zookeepers)
        zk_gen.generate()

    def _write_trust_files(self, topo_dicts, cert_files):
        for topo_id, as_topo, base in _srv_iter(
                topo_dicts, self.out_dir, common=True):
            for path, value in cert_files[topo_id].items():
                write_file(os.path.join(base, path), value)

    def _write_conf_policies(self, topo_dicts):
        """
        Write AS configurations and path policies.
        """
        as_confs = {}
        for topo_id, as_topo, base in _srv_iter(
                topo_dicts, self.out_dir, common=True):
            as_confs.setdefault(topo_id, yaml.dump(
                self._gen_as_conf(as_topo), default_flow_style=False))
            conf_file = os.path.join(base, AS_CONF_FILE)
            write_file(conf_file, as_confs[topo_id])
            # Confirm that config parses cleanly.
            Config.from_file(conf_file)
            copy_file(self.path_policy_file,
                      os.path.join(base, PATH_POLICY_FILE))
        # Confirm that parser actually works on path policy file
        PathPolicy.from_file(self.path_policy_file)

    def _gen_as_conf(self, as_topo):
        master_as_key = base64.b64encode(Random.new().read(16))
        return {
            'MasterASKey': master_as_key.decode("utf-8"),
            'RegisterTime': 5,
            'PropagateTime': 5,
            'CertChainVersion': 0,
            # FIXME(kormat): This seems to always be true..:
            'RegisterPath': True if as_topo["PathServers"] else False,
        }

    def _write_networks_conf(self, networks):
        config = configparser.ConfigParser(interpolation=None)
        for i, net in enumerate(networks):
            sub_conf = {}
            for prog, ip in networks[net].items():
                sub_conf[prog] = ip
            config[net] = sub_conf
        text = StringIO()
        config.write(text)
        write_file(os.path.join(self.out_dir, NETWORKS_FILE), text.getvalue())


class CertGenerator(object):
    def __init__(self, topo_config):
        self.topo_config = topo_config
        self.sig_priv_keys = {}
        self.sig_pub_keys = {}
        self.enc_pub_keys = {}
        self.certs = {}
        self.trcs = {}
        self.cert_files = defaultdict(dict)
        self.trc_files = defaultdict(dict)

    def generate(self):
        self._self_sign_keys()
        self._iterate(self._gen_as_keys)
        self._iterate(self._gen_as_certs)
        self._build_chains()
        self._iterate(self._gen_trc_entry)
        self._iterate(self._sign_trc)
        self._iterate(self._gen_trc_files)
        return self.cert_files, self.trc_files

    def _self_sign_keys(self):
        topo_id = TopoID.from_values(0, 0)
        self.sig_pub_keys[topo_id], self.sig_priv_keys[topo_id] = \
            generate_sign_keypair()
        self.enc_pub_keys[topo_id], _ = generate_sign_keypair()

    def _iterate(self, f):
        for isd_as, as_conf in self.topo_config["ASes"].items():
            f(TopoID(isd_as), as_conf)

    def _gen_as_keys(self, topo_id, as_conf):
        sig_pub, sig_priv = generate_sign_keypair()
        enc_pub, enc_priv = generate_sign_keypair()
        self.sig_priv_keys[topo_id] = sig_priv
        self.sig_pub_keys[topo_id] = sig_pub
        self.enc_pub_keys[topo_id] = enc_pub
        sig_path = get_sig_key_file_path("")
        self.cert_files[topo_id][sig_path] = base64.b64encode(sig_priv).decode()

    def _gen_as_certs(self, topo_id, as_conf):
        # Self-signed if cert_issuer is missing.
        issuer = TopoID(as_conf.get('cert_issuer', str(topo_id)))
        self.certs[topo_id] = Certificate.from_values(
            str(topo_id), self.sig_pub_keys[topo_id],
            self.enc_pub_keys[topo_id], str(issuer), self.sig_priv_keys[issuer],
            INITIAL_CERT_VERSION,
        )

    def _build_chains(self):
        for topo_id, cert in self.certs.items():
            chain = [cert]
            issuer = TopoID(cert.issuer)
            while issuer in self.certs:
                cert = self.certs[issuer]
                if str(issuer) == cert.issuer:
                    break
                chain.append(cert)
                issuer = TopoID(cert.issuer)
            cert_path = get_cert_chain_file_path(
                "", topo_id, INITIAL_CERT_VERSION)
            self.cert_files[topo_id][cert_path] = \
                str(CertificateChain.from_values(chain))

    def _gen_trc_entry(self, topo_id, as_conf):
        if not as_conf.get('core', False):
            return
        if topo_id[0] not in self.trcs:
            self._create_trc(topo_id[0])
        trc = self.trcs[topo_id[0]]
        trc.core_ases[str(topo_id)] = self.certs[topo_id]

    def _create_trc(self, isd):
        self.trcs[isd] = TRC.from_values(
            isd, 0, 1, 1, {'isp.com': 'isp.com_cert_base64'},
            {'ca.com': 'ca.com_cert_base64'}, {}, {}, 'reg_srv_addr',
            'reg_srv_cert', 'dns_srv_addr', 'dns_srv_cert', 'trc_srv_addr', {})

    def _sign_trc(self, topo_id, as_conf):
        if not as_conf.get('core', False):
            return
        trc = self.trcs[topo_id[0]]
        trc_str = trc.to_json(with_signatures=False).encode('utf-8')
        trc.signatures[str(topo_id)] = sign(
            trc_str, self.sig_priv_keys[topo_id])

    def _gen_trc_files(self, topo_id, _):
        for isd in self.trcs:
            trc_path = get_trc_file_path("", isd, INITIAL_TRC_VERSION)
            self.trc_files[topo_id][trc_path] = str(self.trcs[isd])


class TopoGenerator(object):
    def __init__(self, topo_config, out_dir, subnet_gen, zk_config,
                 default_mtu):
        self.topo_config = topo_config
        self.out_dir = out_dir
        self.subnet_gen = subnet_gen
        self.zk_config = zk_config
        self.default_mtu = default_mtu
        self.topo_dicts = {}
        self.hosts = []
        self.zookeepers = defaultdict(dict)
        self.virt_addrs = set()
        self.as_list = defaultdict(list)
        self.links = defaultdict(list)

    def _reg_addr(self, topo_id, elem_id):
        subnet = self.subnet_gen.register(topo_id)
        return subnet.register(elem_id)

    def _reg_link_addrs(self, as1, as2):
        link_name = "%s<->%s" % tuple(sorted((as1, as2)))
        subnet = self.subnet_gen.register(link_name)
        as1_name = "er%ser%s" % (as1, as2)
        as2_name = "er%ser%s" % (as2, as1)
        return subnet.register(as1_name), subnet.register(as2_name)

    def _iterate(self, f):
        for isd_as, as_conf in self.topo_config["ASes"].items():
            f(TopoID(isd_as), as_conf)

    def generate(self):
        self._read_links()
        self._iterate(self._generate_as_topo)
        self._iterate(self._generate_as_list)
        networks = self.subnet_gen.alloc_subnets()
        self._write_as_topos()
        self._write_as_list()
        return self.topo_dicts, self.zookeepers, networks

    def _read_links(self):
        for attrs in self.topo_config["links"]:
            # Pop the basic attributes, then append the remainder to the link
            # entry.
            a = TopoID(attrs.pop("a"))
            b = TopoID(attrs.pop("b"))
            ltype = ltype_a = ltype_b = attrs.pop("ltype")
            if ltype == LINK_PARENT:
                ltype_a = LINK_CHILD
                ltype_b = LINK_PARENT
            self.links[a].append((ltype_a, b, attrs))
            self.links[b].append((ltype_b, a, attrs))

    def _generate_as_topo(self, topo_id, as_conf):
        mtu = as_conf.get('mtu', self.default_mtu)
        assert mtu >= SCION_MIN_MTU, mtu
        self.topo_dicts[topo_id] = {
            'Core': as_conf.get('core', False), 'ISD_AS': str(topo_id),
            'Zookeepers': {}, 'MTU': mtu,
        }
        for i in SCION_SERVICE_NAMES:
            self.topo_dicts[topo_id][i] = {}
        self._gen_srv_entries(topo_id, as_conf)
        self._gen_er_entries(topo_id)
        self._gen_zk_entries(topo_id, as_conf)

    def _gen_srv_entries(self, topo_id, as_conf):
        for conf_key, def_num, nick, topo_key in (
            ("beacon_servers", DEFAULT_BEACON_SERVERS, "bs", "BeaconServers"),
            ("certificate_servers", DEFAULT_CERTIFICATE_SERVERS, "cs",
             "CertificateServers"),
            ("path_servers", DEFAULT_PATH_SERVERS, "ps", "PathServers"),
            ("sibra_servers", DEFAULT_SIBRA_SERVERS, "sb", "SibraServers"),
        ):
            self._gen_srv_entry(
                topo_id, as_conf, conf_key, def_num, nick, topo_key)

    def _gen_srv_entry(self, topo_id, as_conf, conf_key, def_num, nick,
                       topo_key):
        count = as_conf.get(conf_key, def_num)
        for i in range(1, count + 1):
            elem_id = "%s%s-%s" % (nick, topo_id, i)
            d = {}
            d["Addr"] = self._reg_addr(topo_id, elem_id)
            d["Port"] = random.randint(30050, 30100)
            self.topo_dicts[topo_id][topo_key][elem_id] = d

    def _gen_er_entries(self, topo_id):
        er_id = 1
        for ltype, remote, attrs in self.links[topo_id]:
            self._gen_er_entry(topo_id, er_id, remote, ltype, attrs)
            er_id += 1

    def _gen_er_entry(self, local, er_id, remote, remote_type, attrs):
        elem_id = "er%ser%s" % (local, remote)
        public_addr, remote_addr = self._reg_link_addrs(
            local, remote)
        self.topo_dicts[local]["EdgeRouters"][elem_id] = {
            'Addr': self._reg_addr(local, elem_id),
            'Port': random.randint(30050, 30100),
            'Interface': {
                'IFID': er_id,
                'ISD_AS': str(remote),
                'LinkType': remote_type,
                'Addr': public_addr,
                'ToAddr': remote_addr,
                'UdpPort': SCION_ROUTER_PORT,
                'ToUdpPort': SCION_ROUTER_PORT,
                'Bandwidth': attrs.get('bw', DEFAULT_LINK_BW),
                'MTU': attrs.get('mtu', DEFAULT_MTU),
            }
        }

    def _gen_zk_entries(self, topo_id, as_conf):
        zk_conf = {}
        if "zookeepers" in as_conf:
            zk_conf = as_conf["zookeepers"]
        elif "zookeepers" in self.topo_config.get("defaults", {}):
            zk_conf = self.topo_config["defaults"]["zookeepers"]
        for key, val in zk_conf.items():
            self._gen_zk_entry(topo_id, key, val)

    def _gen_zk_entry(self, topo_id, zk_id, zk_conf):
        zk = ZKTopo(zk_conf, self.zk_config)
        if zk.manage:
            elem_id = "zk%s-%s" % (topo_id, zk_id)
            addr = zk.addr = self._reg_addr(topo_id, elem_id)
            self.zookeepers[topo_id][elem_id] = zk_id, zk
        else:
            addr = str(zk.addr)
        self.topo_dicts[topo_id]["Zookeepers"][zk_id] = {
            'Addr': addr,
            'Port': zk.clientPort,
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
            contents = yaml.dump(self.topo_dicts[topo_id],
                                 default_flow_style=False)
            write_file(path, contents)
            # Test if topo file parses cleanly
            Topology.from_file(path)

    def _write_as_list(self):
        list_path = os.path.join(self.out_dir, AS_LIST_FILE)
        write_file(list_path, yaml.dump(dict(self.as_list)))


class SupervisorGenerator(object):
    def __init__(self, out_dir, topo_dicts, zookeepers, zk_config, mininet):
        self.out_dir = out_dir
        self.topo_dicts = topo_dicts
        self.zookeepers = zookeepers
        self.zk_config = zk_config
        self.mininet = mininet

    def generate(self):
        self._write_dispatcher_conf()
        for topo_id, topo in self.topo_dicts.items():
            self._as_conf(topo_id, topo)

    def _as_conf(self, topo_id, topo):
        entries = []
        base = self._get_base_path(topo_id)
        for key, cmd in (
            ("BeaconServers", "bin/beacon_server"),
            ("CertificateServers", "bin/cert_server"),
            ("EdgeRouters", "bin/router"),
            ("PathServers", "bin/path_server"),
            ("SibraServers", "bin/sibra_server"),
        ):
            entries.extend(self._std_entries(topo, key, cmd, base))
        entries.extend(self._zk_entries(topo_id))
        self._write_as_conf(topo_id, entries)

    def _std_entries(self, topo, topo_key, cmd, base):
        entries = []
        for elem in topo.get(topo_key, {}):
            conf_dir = os.path.join(base, elem)
            entries.append((elem, [cmd, elem, conf_dir]))
        return entries

    def _zk_entries(self, topo_id):
        if topo_id not in self.zookeepers:
            return []
        entries = []
        for name, (_, zk) in self.zookeepers[topo_id].items():
            entries.append((name, zk.super_conf(topo_id, name, self.out_dir)))
        return entries

    def _write_as_conf(self, topo_id, entries):
        config = configparser.ConfigParser(interpolation=None)
        names = []
        includes = []
        base = os.path.join(self.out_dir, topo_id.ISD(), topo_id.AS())
        for elem, entry in sorted(entries, key=lambda x: x[0]):
            names.append(elem)
            conf_path = os.path.join(base, elem, SUPERVISOR_CONF)
            includes.append(os.path.join(elem, SUPERVISOR_CONF))
            self._write_elem_conf(elem, entry, conf_path)
            if self.mininet:
                self._write_elem_mininet_conf(elem, conf_path)
        config["group:as%s" % topo_id] = {"programs": ",".join(names)}
        text = StringIO()
        config.write(text)
        conf_path = os.path.join(self.out_dir, topo_id.ISD(), topo_id.AS(),
                                 SUPERVISOR_CONF)
        write_file(conf_path, text.getvalue())

    def _write_elem_conf(self, elem, entry, conf_path):
        config = configparser.ConfigParser(interpolation=None)
        config["program:%s" % elem] = self._common_entry(elem, entry)
        if self.mininet and not elem.startswith("er"):
            disp = "dp-" + elem
            config["program:%s" % disp] =\
                self._common_entry(disp, ["bin/dispatcher"])
        text = StringIO()
        config.write(text)
        write_file(conf_path, text.getvalue())

    def _write_elem_mininet_conf(self, elem, conf_path):
        tmpl = Template(read_file("topology/mininet/supervisord.conf"))
        mn_conf_path = os.path.join(self.out_dir, "mininet", "%s.conf" % elem)
        rel_conf_path = os.path.relpath(
            conf_path, os.path.join(self.out_dir, "mininet"))
        write_file(mn_conf_path,
                   tmpl.substitute(elem=elem, conf_path=rel_conf_path,
                                   user=getpass.getuser()))

    def _write_dispatcher_conf(self):
        elem = "dispatcher"
        conf_path = os.path.join(self.out_dir, elem, SUPERVISOR_CONF)
        self._write_elem_conf(elem, ["bin/dispatcher"], conf_path)

    def _get_base_path(self, topo_id):
        return os.path.join(self.out_dir, topo_id.ISD(), topo_id.AS())

    def _common_entry(self, name, cmd_args):
        entry = {
            'autostart': 'false' if self.mininet else 'false',
            'autorestart': 'false',
            'redirect_stderr': 'true',
            'environment': 'PYTHONPATH=.',
            'stdout_logfile_maxbytes': 0,
            'stdout_logfile': "logs/%s.OUT" % name,
            'startretries': 0,
            'startsecs': 5,
            'command': " ".join(['"%s"' % arg for arg in cmd_args]),
        }
        if name == "dispatcher":
            entry['startsecs'] = 1
        if self.mininet:
            entry['autostart'] = 'true'
        return entry


class ZKConfGenerator(object):
    def __init__(self, out_dir, zookeepers):
        self.out_dir = out_dir
        self.zookeepers = zookeepers
        self.datalog_dirs = []

    def generate(self):
        for topo_id, zks in self.zookeepers.items():
            self._write_as_zk_configs(topo_id, zks)
        self._write_datalog_dirs()

    def _write_as_zk_configs(self, topo_id, zks):
        # Build up server block
        servers = []
        for id_, zk in zks.values():
            servers.append("server.%s=%s:%d:%d" %
                           (id_, zk.addr.ip, zk.leaderPort, zk.electionPort))
        server_block = "\n".join(sorted(servers))
        base_dir = os.path.join(self.out_dir, topo_id.ISD(), topo_id.AS())
        for name, (id_, zk) in zks.items():
            copy_file(DEFAULT_ZK_LOG4J,
                      os.path.join(base_dir, name, "log4j.properties"))
            text = StringIO()
            datalog_dir = os.path.join(ZOOKEEPER_TMPFS_DIR, name)
            text.write("%s\n\n" % zk.zk_conf(
                os.path.join(base_dir, name, "data"), datalog_dir,
            ))
            text.write("%s\n" % server_block)
            write_file(os.path.join(base_dir, name, 'zoo.cfg'), text.getvalue())
            write_file(os.path.join(base_dir, name, "data", "myid"),
                       "%s\n" % id_)
            self.datalog_dirs.append(datalog_dir)

    def _write_datalog_dirs(self):
        text = StringIO()
        text.write("#!/bin/bash\n\n")
        text.write(
            "if [ ! -e %(dir)s ]; then\n"
            "  echo 'Creating %(dir)s & restarting zookeeper'\n"
            "  sudo mkdir -p %(dir)s\n"
            "  sudo chown -R zookeeper: %(dir)s\n"
            "  sudo service zookeeper restart\n"
            "fi\n" % {"dir": ZOOKEEPER_HOST_TMPFS_DIR}
        )
        for d in self.datalog_dirs:
            text.write("mkdir -p %s\n" % d)
        write_file(os.path.join(self.out_dir, "zk_datalog_dirs.sh"),
                   text.getvalue())


class TopoID(ISD_AS):
    def ISD(self):
        return "ISD%s" % self._isd

    def AS(self):
        return "AS%s" % self._as

    def __lt__(self, other):
        return str(self) < str(other)

    def __repr__(self):
        return "<TopoID: %s>" % self


class ZKTopo(object):
    def __init__(self, topo_config, zk_config):
        self.addr = None
        self.topo_config = topo_config
        self.zk_config = zk_config
        self.manage = self.topo_config.get("manage", False)
        if not self.manage:
            # A ZK we don't manage must have an assigned IP in the topology
            self.addr = ip_interface(self.topo_config["addr"])
        self.clientPort = self._get_def("clientPort")
        self.leaderPort = self._get_def("leaderPort")
        self.electionPort = self._get_def("electionPort")
        self.maxClientCnxns = self._get_def("maxClientCnxns")

    def _get_def(self, key):
        return self.topo_config.get(key, self.zk_config["Default"][key])

    def zk_conf(self, data_dir, data_log_dir):
        c = []
        for s in ('tickTime', 'initLimit', 'syncLimit', 'maxClientCnxns'):
            c.append("%s=%s" % (s, self._get_def(s)))
        c.append("dataDir=%s" % data_dir)
        c.append("dataLogDir=%s" % data_log_dir)
        c.append("clientPort=%s" % self.clientPort)
        c.append("clientPortAddress=%s" % self.addr.ip)
        c.append("autopurge.purgeInterval=1")
        return "\n".join(c)

    def super_conf(self, topo_id, name, out_dir):
        base_dir = os.path.join(out_dir, topo_id.ISD(), topo_id.AS(), name)
        cfg_path = os.path.join(base_dir, "zoo.cfg")
        class_path = ":".join([
            base_dir, self.zk_config["Environment"]["CLASSPATH"],
        ])
        return [
            "java", "-cp", class_path,
            '-Dzookeeper.log.file=logs/%s.log' % name,
            self.zk_config["Environment"]["ZOOMAIN"], cfg_path,
        ]


class SubnetGenerator(object):
    def __init__(self, network):
        self._net = ip_network(network)
        if "/" not in network:
            logging.critical("No prefix length specified for network '%s'",
                             network)
            sys.exit(1)
        self._subnets = defaultdict(lambda: AddressGenerator())
        self._allocations = defaultdict(list)
        # Initialise the allocations with the supplied network, making sure to
        # exclude 127.0.0.0/30 if it's contained in the network.
        # - 127.0.0.0 is treated as a broadcast address by the kernel
        # - 127.0.0.1 is the normal loopback address
        # - 127.0.0.[23] are used for clients to bind to for testing purposes.
        v4_lo = ip_network("127.0.0.0/30")
        if self._net.overlaps(v4_lo):
            self._exclude_net(self._net, v4_lo)
        else:
            self._allocations[self._net.prefixlen].append(self._net)

    def register(self, location):
        return self._subnets[location]

    def alloc_subnets(self):
        max_prefix = self._net.max_prefixlen
        networks = {}
        for topo, subnet in sorted(self._subnets.items(), key=lambda x: str(x)):
            # Figure out what size subnet we need. If it's a link, then we just
            # need a /31 (or /127), otherwise add 2 to the subnet size to cover
            # the network and broadcast addresses.
            if len(subnet) == 2:
                req_prefix = max_prefix - 1
            else:
                req_prefix = max_prefix - math.ceil(math.log2(len(subnet) + 2))
            # Search all subnets from that size upwards
            for prefix in range(req_prefix, -1, -1):
                if not self._allocations[prefix]:
                    # No subnets available at this size
                    continue
                alloc = self._allocations[prefix].pop()
                # Carve out subnet of the required size
                new_net = next(alloc.subnets(new_prefix=req_prefix))
                logging.debug("Allocating %s from %s for subnet size %d" %
                              (new_net, alloc, len(subnet)))
                networks[new_net] = subnet.alloc_addrs(new_net)
                # Repopulate the allocations list with the left-over space
                self._exclude_net(alloc, new_net)
                break
            else:
                logging.critical("Unable to allocate /%d subnet" % req_prefix)
                sys.exit(1)
        return networks

    def _exclude_net(self, alloc, net):
        for net in alloc.address_exclude(net):
            self._allocations[net.prefixlen].append(net)


class AddressGenerator(object):
    def __init__(self):
        self._addrs = defaultdict(lambda: AddressProxy())

    def register(self, id_):
        return self._addrs[id_]

    def alloc_addrs(self, subnet):
        hosts = subnet.hosts()
        interfaces = {}
        for elem, proxy in sorted(self._addrs.items()):
            intf = ip_interface("%s/%s" % (next(hosts), subnet.prefixlen))
            interfaces[elem] = intf
            proxy.set_intf(intf)
        return interfaces

    def __len__(self):
        return len(self._addrs)


class AddressProxy(yaml.YAMLObject):
    yaml_tag = ""

    def __init__(self):
        self._intf = None
        self.ip = None

    def set_intf(self, intf):
        self._intf = intf
        self.ip = self._intf.ip

    def __str__(self):
        return str(self._intf)

    @classmethod
    def to_yaml(cls, dumper, inst):
        return dumper.represent_scalar('tag:yaml.org,2002:str', str(inst))


def _srv_iter(topo_dicts, out_dir, common=False):
    for topo_id, as_topo in topo_dicts.items():
        base = os.path.join(out_dir, topo_id.ISD(), topo_id.AS())
        for service in SCION_SERVICE_NAMES:
            for elem in as_topo[service]:
                yield topo_id, as_topo, os.path.join(base, elem)
        if common:
            yield topo_id, as_topo, os.path.join(base, COMMON_DIR)


def main():
    """
    Main function.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--topo-config', default=DEFAULT_TOPOLOGY_FILE,
                        help='Default topology config')
    parser.add_argument('-p', '--path-policy', default=DEFAULT_PATH_POLICY_FILE,
                        help='Path policy file')
    parser.add_argument('-m', '--mininet', action='store_true',
                        help='Use Mininet to create a virtual network topology')
    parser.add_argument('-n', '--network',
                        help='Network to create subnets in (E.g. "127.0.0.0/8"')
    parser.add_argument('-o', '--output-dir', default=GEN_PATH,
                        help='Output directory')
    parser.add_argument('-z', '--zk-config', default=DEFAULT_ZK_CONFIG,
                        help='Zookeeper configuration file')
    args = parser.parse_args()
    confgen = ConfigGenerator(
        args.output_dir, args.topo_config, args.path_policy, args.zk_config,
        args.network, args.mininet)
    confgen.generate_all()


if __name__ == "__main__":
    main()
