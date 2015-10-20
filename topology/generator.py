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
import json
import logging
import os
import sys
from collections import defaultdict
from io import StringIO
from ipaddress import ip_address, ip_network

# External packages
from Crypto import Random
from dnslib.label import DNSLabel

# SCION
from lib.config import Config
from lib.crypto.asymcrypto import (
    generate_cryptobox_keypair,
    generate_signature_keypair,
    sign,
)
from lib.crypto.certificate import Certificate, CertificateChain, TRC
from lib.defines import GEN_PATH, SCION_ROUTER_PORT
from lib.path_store import PathPolicy
from lib.topology import Topology
from lib.util import (
    copy_file,
    get_cert_chain_file_path,
    get_enc_key_file_path,
    get_sig_key_file_path,
    get_trc_file_path,
    load_json_file,
    write_file,
)

DEFAULT_ADCONFIGURATIONS_FILE = "topology/ADConfigurations.json"
DEFAULT_PATH_POLICY_FILE = "topology/PathPolicy.json"
DEFAULT_ZK_CONFIG = "topology/Zookeeper.json"
DEFAULT_ZK_LOG4J = "topology/Zookeeper.log4j"

GEN_DIR = 'gen'
CERT_DIR = 'certificates'
CONF_DIR = 'configurations'
TOPO_DIR = 'topologies'
SIG_KEYS_DIR = 'signature_keys'
ENC_KEYS_DIR = 'encryption_keys'
PATH_POL_DIR = 'path_policies'
SUPERVISOR_DIR = 'supervisor'
SIM_DIR = 'SIM'
SIM_CONF_FILE = 'sim.conf'
HOSTS_FILE = 'hosts'
MININET_CONF = 'mininet.conf'

ZOOKEEPER_DIR = 'zookeeper'
ZOOKEEPER_CFG = "zoo.cfg"
ZOOKEEPER_HOST_TMPFS_DIR = "/run/shm/host-zk"
ZOOKEEPER_TMPFS_DIR = "/run/shm/scion-zk"

CORE_AD = 'CORE'
INTERMEDIATE_AD = 'INTERMEDIATE'
LEAF_AD = 'LEAF'

DEFAULT_BEACON_SERVERS = 1
DEFAULT_CERTIFICATE_SERVERS = 1
DEFAULT_PATH_SERVERS = 1
DEFAULT_DNS_SERVERS = 1
INITIAL_CERT_VERSION = 0
INITIAL_TRC_VERSION = 0
DEFAULT_DNS_DOMAIN = DNSLabel("scion")

DEFAULT_NETWORK = "127.0.0.0/8"
DEFAULT_MININET_NETWORK = "100.64.0.0/10"
DEFAULT_SUBNET_PREFIX = 26


class ConfigGenerator(object):
    """
    Configuration and/or topology generator.
    """
    def __init__(self, out_dir=GEN_PATH,
                 adconfigurations_file=DEFAULT_ADCONFIGURATIONS_FILE,
                 path_policy_file=DEFAULT_PATH_POLICY_FILE,
                 zk_config_file=DEFAULT_ZK_CONFIG, network=None,
                 is_sim=False, use_mininet=False):
        """
        Initialize an instance of the class ConfigGenerator.

        :param string out_dir: path to the topology folder.
        :param string adconfigurations_file: path to ADConfigurations.json
        :param string path_policy_file: path to PathPolicy.json
        :param string zk_config_file: path to Zookeeper.json
        :param string network:
            Network to create subnets in, of the form x.x.x.x/y
        :param bool is_sim: Generate conf files for the Simulator
        :param bool use_mininet: Use Mininet
        """
        self.out_dir = out_dir
        self.ad_configs = load_json_file(adconfigurations_file)
        self.zk_config = load_json_file(zk_config_file)
        self.path_policy_file = path_policy_file
        self.is_sim = is_sim
        self.mininet = use_mininet
        self.default_zookeepers = {}
        self._read_defaults(network)

    def _read_defaults(self, network):
        """
        Configure default network and ZooKeeper setup.
        """
        defaults = self.ad_configs.get("defaults", {})
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
            self.default_zookeepers[key] = ZKTopo(
                val, self.zk_config["Default"])

    def generate_all(self):
        """
        Generate all needed files.
        """
        self._generate_certs()
        topo_dicts, zookeepers, networks = self._generate_topology()
        self._generate_supervisor(topo_dicts, zookeepers)
        if self.is_sim:
            self._generate_sim_conf(topo_dicts)
        self._generate_zk_conf(zookeepers)
        self._write_conf_files()
        self._write_path_policy_files()
        if self.mininet:
            self._write_mininet_conf(networks)

    def _generate_certs(self):
        certgen = CertGenerator(self.ad_configs, self.out_dir)
        certgen.generate()

    def _generate_topology(self):
        topo_gen = TopoGenerator(self.ad_configs, self.out_dir, self.subnet_gen,
                                 self.zk_config, self.is_sim)
        return topo_gen.generate()

    def _generate_supervisor(self, topo_dicts, zookeepers):
        super_gen = SupervisorGenerator(self.out_dir, topo_dicts, zookeepers,
                                        self.zk_config)
        super_gen.generate()

    def _generate_sim_conf(self, topo_dicts):
        sim_gen = SimulatorGenerator(self.out_dir, topo_dicts)
        sim_gen.generate()

    def _generate_zk_conf(self, zookeepers):
        zk_gen = ZKConfGenerator(self.out_dir, zookeepers)
        zk_gen.generate()

    def _write_conf_files(self):
        """
        Generate the AD configurations and store them into files.
        """
        for isd_ad_id, ad_conf in self.ad_configs["ADs"].items():
            topo_id = TopoID(isd_ad_id)
            conf_file = os.path.join(self.out_dir, topo_id.ISD(), CONF_DIR,
                                     "%s.conf" % topo_id.ISD_AD())
            master_ad_key = base64.b64encode(Random.new().read(16))
            conf_dict = {'MasterADKey': master_ad_key.decode("utf-8"),
                         'RegisterTime': 5,
                         'PropagateTime': 5,
                         'MTU': 1500,
                         'CertChainVersion': 0}
            if self.is_sim:
                conf_dict['PropagateTime'] = 10
                conf_dict['RegisterTime'] = 10
            if (ad_conf['level'] != INTERMEDIATE_AD or
                    "path_servers" in ad_conf):
                conf_dict['RegisterPath'] = 1
            else:
                conf_dict['RegisterPath'] = 0
            write_file(conf_file, "%s\n" %
                       json.dumps(conf_dict, sort_keys=True, indent=4))
            # Test if parser works
            Config.from_file(conf_file)

    def _write_path_policy_files(self):
        """
        Generate the AD path policies and store them into files.
        """
        for isd_ad_id in self.ad_configs["ADs"]:
            topo_id = TopoID(isd_ad_id)
            dst = os.path.join(self.out_dir, topo_id.ISD(), PATH_POL_DIR,
                               "%s.json" % topo_id.ISD_AD())
            copy_file(self.path_policy_file, dst)
            # Test if parser works
            PathPolicy.from_file(dst)

    def _write_mininet_conf(self, networks):
        config = configparser.ConfigParser(interpolation=None)
        for i, net in enumerate(networks):
            sub_conf = {}
            for prog, ip in networks[net].items():
                sub_conf[prog] = ip
            config[net] = sub_conf
        text = StringIO()
        config.write(text)
        write_file(os.path.join(self.out_dir, MININET_CONF), text.getvalue())


class CertGenerator(object):
    def __init__(self, ad_configs, out_dir):
        self.ad_configs = ad_configs
        self.out_dir = out_dir
        self.sig_priv_keys = {}
        self.sig_pub_keys = {}
        self.enc_pub_keys = {}
        self.certs = {}
        self.chains = {}
        self.trcs = {}

    def generate(self):
        self._self_sign_keys()
        self._iterate(self._write_ad_keys)
        self._iterate(self._generate_ad_certs)
        self._build_chains()
        self._write_ad_certs()
        self._iterate(self._generate_trc_entry)
        self._iterate(self._sign_trc)
        self._iterate(self._write_trc)

    def _self_sign_keys(self):
        topo_id = TopoID.from_values(0, 0)
        self.sig_pub_keys[topo_id], self.sig_priv_keys[topo_id] = \
            generate_signature_keypair()
        self.enc_pub_keys[topo_id], _ = generate_cryptobox_keypair()

    def _iterate(self, f):
        for isd_ad_id, ad_conf in self.ad_configs["ADs"].items():
            f(TopoID(isd_ad_id), ad_conf)

    def _write_ad_keys(self, topo_id, ad_conf):
        sig_pub, sig_priv = generate_signature_keypair()
        enc_pub, enc_priv = generate_cryptobox_keypair()
        self.sig_priv_keys[topo_id] = sig_priv
        self.sig_pub_keys[topo_id] = sig_pub
        self.enc_pub_keys[topo_id] = enc_pub
        sig_key_file = get_sig_key_file_path(
            topo_id.isd, topo_id.ad, self.out_dir)
        enc_key_file = get_enc_key_file_path(
            topo_id.isd, topo_id.ad, self.out_dir)
        write_file(sig_key_file, base64.b64encode(sig_priv).decode())
        write_file(enc_key_file, base64.b64encode(enc_priv).decode())

    def _generate_ad_certs(self, topo_id, ad_conf):
        if ad_conf['level'] == CORE_AD:
            return
        if 'cert_issuer' not in ad_conf:
            logging.warning("No 'cert_issuer' attribute for "
                            "a non-core AD: %s", topo_id)
        issuer = TopoID(ad_conf.get('cert_issuer', '0-0'))
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
                chain.append(cert)
                issuer = TopoID(cert.issuer)
            self.chains[topo_id] = CertificateChain.from_values(chain)

    def _write_ad_certs(self):
        for topo_id, chain in self.chains.items():
            cert_file = get_cert_chain_file_path(
                topo_id.isd, topo_id.ad, topo_id.isd, topo_id.ad,
                INITIAL_CERT_VERSION, isd_dir=self.out_dir
            )
            write_file(cert_file, str(chain))
            # Test if parser works
            CertificateChain(cert_file)

    def _generate_trc_entry(self, topo_id, ad_conf):
        if ad_conf['level'] != CORE_AD:
            return
        cert = Certificate.from_values(
            str(topo_id), self.sig_pub_keys[topo_id],
            self.enc_pub_keys[topo_id],
            str(topo_id), self.sig_priv_keys[topo_id], 0)
        if topo_id.isd not in self.trcs:
            self._create_trc(topo_id.isd)
        trc = self.trcs[topo_id.isd]
        trc.core_ads[str(topo_id)] = cert

    def _create_trc(self, isd_id):
        self.trcs[isd_id] = TRC.from_values(
            int(isd_id), 0, 1, 1, {'isp.com': 'isp.com_cert_base64'},
            {'ca.com': 'ca.com_cert_base64'}, {}, {}, 'reg_srv_addr',
            'reg_srv_cert', 'dns_srv_addr', 'dns_srv_cert', 'trc_srv_addr', {})

    def _sign_trc(self, topo_id, ad_conf):
        if ad_conf['level'] != CORE_AD:
            return
        trc = self.trcs[topo_id.isd]
        trc_str = trc.__str__(with_signatures=False).encode('utf-8')
        trc.signatures[str(topo_id)] = sign(
            trc_str, self.sig_priv_keys[topo_id])

    def _write_trc(self, topo_id, _):
        trc = self.trcs[topo_id.isd]
        dst_path = get_trc_file_path(
            topo_id.isd, topo_id.ad, topo_id.isd, 0, self.out_dir)
        write_file(dst_path, str(trc))
        # Test if parser works
        TRC(dst_path).verify()


class TopoGenerator(object):
    def __init__(self, ad_configs, out_dir, subnet_gen, zk_config, is_sim):
        self.ad_configs = ad_configs
        self.out_dir = out_dir
        self.subnet_gen = subnet_gen
        self.zk_config = zk_config
        self.is_sim = is_sim
        self.topo_dicts = {}
        self.hosts = StringIO()
        self.zookeepers = defaultdict(dict)
        self.networks = defaultdict(dict)
        self.link_net = SubnetGenerator(self.subnet_gen.link_network, 31)

    def _get_addr(self, topo_id, elem_id):
        """
        Get an address and address type for an element, assigning a new address
        if necessary.
        """
        addr_gen = self.subnet_gen.get(topo_id)
        addr, subnet = addr_gen.get(elem_id)
        self.networks[subnet][elem_id] = addr
        return addr, _addr_type(addr)

    def _get_link_addrs(self, ad1, ad2):
        link_name = "%s<->%s" % tuple(sorted((ad1, ad2)))
        addr_gen = self.link_net.get(link_name)
        ad1_name = "er%ser%s" % (ad1, ad2)
        ad2_name = "er%ser%s" % (ad2, ad1)
        ad1_addr, subnet = addr_gen.get(ad1_name)
        ad2_addr, _ = addr_gen.get(ad2_name)
        self.networks[subnet][ad1_name] = ad1_addr
        self.networks[subnet][ad2_name] = ad2_addr
        return ad1_addr, ad2_addr, _addr_type(ad1_addr)

    def _iterate(self, f):
        for isd_ad_id, ad_conf in self.ad_configs["ADs"].items():
            f(TopoID(isd_ad_id), ad_conf)

    def generate(self):
        self._iterate(self._generate_ad_topo)
        self._iterate(self._write_ad_topo)
        self._write_hosts()
        return self.topo_dicts, self.zookeepers, self.networks

    def _generate_ad_topo(self, topo_id, ad_conf):
        dns_domain = DNSLabel(ad_conf.get("dns_domain", DEFAULT_DNS_DOMAIN))
        dns_domain = dns_domain.add(
            "isd%s" % topo_id.isd).add("ad%s" % topo_id.ad)
        self.topo_dicts[topo_id] = {
            'Core': ad_conf['level'] == CORE_AD,
            'ISDID': int(topo_id.isd), 'ADID': int(topo_id.ad),
            'DnsDomain': str(dns_domain),
            'BeaconServers': {}, 'CertificateServers': {},
            'PathServers': {}, 'DNSServers': {},
            'EdgeRouters': {}, 'Zookeepers': {},
        }
        self._gen_srv_entries(topo_id, ad_conf, dns_domain)
        self._gen_er_entries(topo_id, ad_conf)
        self._gen_zk_entries(topo_id, ad_conf)

    def _gen_srv_entries(self, topo_id, ad_conf, dns_domain):
        for conf_key, def_num, nick, topo_key in (
            ("beacon_servers", DEFAULT_BEACON_SERVERS, "bs", "BeaconServers"),
            ("certificate_servers", DEFAULT_CERTIFICATE_SERVERS, "cs",
             "CertificateServers"),
            ("path_servers", DEFAULT_PATH_SERVERS, "ps", "PathServers"),
            ("dns_servers", DEFAULT_DNS_SERVERS, "ds", "DNSServers"),
        ):
            self._gen_srv_entry(
                topo_id, ad_conf, conf_key, def_num, nick, topo_key)
        self._gen_hosts_entries(topo_id, dns_domain)

    def _gen_srv_entry(self, topo_id, ad_conf, conf_key, def_num, nick,
                       topo_key):
        count = ad_conf.get(conf_key, def_num)
        for i in range(1, count + 1):
            elem_id = "%s%s-%s" % (nick, topo_id, i)
            addr, addr_type = self._get_addr(topo_id, elem_id)
            self.topo_dicts[topo_id][topo_key][i] = {
                'AddrType': addr_type, 'Addr': str(addr),
            }

    def _gen_hosts_entries(self, topo_id, dns_domain):
        for dns_srv in self.topo_dicts[topo_id]["DNSServers"].values():
            self.hosts.write(
                "%s\tds.%s\n" % (dns_srv["Addr"], str(dns_domain).rstrip(".")))

    def _gen_er_entries(self, topo_id, ad_conf):
        er_id = 1
        for remote, link_type in ad_conf["links"].items():
            self._gen_er_entry(topo_id, er_id, TopoID(remote), link_type)
            er_id += 1

    def _gen_er_entry(self, local, er_id, remote, remote_type):
        local_if = "er%ser%s" % (local, remote)
        local_addr, local_type = self._get_addr(local, local_if)
        public_addr, remote_addr, public_addr_type = self._get_link_addrs(
            local, remote)
        self.topo_dicts[local]["EdgeRouters"][er_id] = {
            'AddrType': local_type, 'Addr': str(local_addr),
            'Interface': {
                'IFID': er_id,
                'NeighborISD': int(remote.isd),
                'NeighborAD': int(remote.ad),
                'NeighborType': remote_type,
                'AddrType': public_addr_type,
                'Addr': str(public_addr),
                'ToAddr': str(remote_addr),
                'UdpPort': SCION_ROUTER_PORT,
                'ToUdpPort': SCION_ROUTER_PORT,
            }
        }

    def _gen_zk_entries(self, topo_id, ad_conf):
        zk_conf = {}
        if "zookeepers" in ad_conf:
            zk_conf = ad_conf["zookeepers"]
        elif "zookeepers" in self.ad_configs.get("defaults", {}):
            zk_conf = self.ad_configs["defaults"]["zookeepers"]
        for key, val in zk_conf.items():
            self._gen_zk_entry(topo_id, key, val)

    def _gen_zk_entry(self, topo_id, zk_id, zk_conf):
        zk = ZKTopo(zk_conf, self.zk_config["Default"])
        if zk.manage:
            elem_id = "zk%s-%s" % (topo_id, zk_id)
            zk.addr, _ = self._get_addr(topo_id, elem_id)
            self.zookeepers[topo_id][zk_id] = zk
        self.topo_dicts[topo_id]["Zookeepers"][zk_id] = {
            'AddrType': _addr_type(zk.addr),
            'Addr': str(zk.addr),
            'Port': zk.clientPort,
        }

    def _write_ad_topo(self, topo_id, _):
        path = os.path.join(self.out_dir, topo_id.ISD(), TOPO_DIR, "%s.json" %
                            topo_id.ISD_AD())
        write_file(path, json.dumps(
            self.topo_dicts[topo_id], sort_keys=True, indent=4))
        Topology.from_file(path)

    def _write_hosts(self):
        hosts_path = os.path.join(self.out_dir, HOSTS_FILE)
        write_file(hosts_path, self.hosts.getvalue())


class SupervisorGenerator(object):
    def __init__(self, out_dir, topo_dicts, zookeepers, zk_config):
        self.out_dir = out_dir
        self.topo_dicts = topo_dicts
        self.zookeepers = zookeepers
        self.zk_config = zk_config

    def generate(self):
        for topo_id, topo in self.topo_dicts.items():
            self._ad_conf(topo_id, topo)

    def _ad_conf(self, topo_id, topo):
        entries = []
        topo_path = self._topo_path(topo_id)
        conf_path = self._conf_path(topo_id)
        path_pol_path = self._path_policy_path(topo_id)
        trc_path = self._trc_path(topo_id)
        entries.extend(self._std_entries(
            topo_id, topo, "BeaconServers", "bs", "beacon_server.py",
            [topo_path, conf_path, path_pol_path]))
        entries.extend(self._std_entries(
            topo_id, topo, "CertificateServers", "cs", "cert_server.py",
            [topo_path, conf_path, trc_path]))
        entries.extend(self._std_entries(
            topo_id, topo, "PathServers", "ps", "path_server.py",
            [topo_path, conf_path]))
        entries.extend(self._std_entries(
            topo_id, topo, "DNSServers", "ds", "dns_server.py",
            [topo["DnsDomain"], topo_path]))
        entries.extend(self._er_entries(topo_id, topo, [topo_path, conf_path]))
        entries.extend(self._zk_entries(topo_id))
        self._write_ad_conf(topo_id, entries)

    def _std_entries(self, topo_id, topo, topo_key, short, cmd, args):
        entries = []
        for id_ in topo.get(topo_key, {}):
            name = "%s%s-%s-%s" % (short, topo_id.isd, topo_id.ad, id_)
            cmd_args = ["infrastructure/%s" % cmd, id_] + args + \
                ["logs/%s.log" % name]
            entries.append((name, cmd_args))
        return entries

    def _er_entries(self, topo_id, topo, args):
        entries = []
        for id_, val in topo.get("EdgeRouters", {}).items():
            neigh_isd = val["Interface"]["NeighborISD"]
            neigh_ad = val["Interface"]["NeighborAD"]
            name = "er%s-%ser%s-%s" % (topo_id.isd, topo_id.ad,
                                       neigh_isd, neigh_ad)
            cmd_args = ["infrastructure/router.py", id_] + args + \
                ["logs/%s.log" % name]
            entries.append((name, cmd_args))
        return entries

    def _zk_entries(self, topo_id):
        if topo_id not in self.zookeepers:
            return []
        entries = []
        base_dir = os.path.join(self.out_dir, topo_id.ISD(), ZOOKEEPER_DIR,
                                topo_id.ISD_AD())
        for id_, zk in self.zookeepers[topo_id].items():
            name = "zk%s-%s-%s" % (topo_id.isd, topo_id.ad, id_)
            cfg_path = os.path.join(base_dir, "zoo.cfg.%s" % id_)
            class_path = ":".join([
                base_dir, self.zk_config["Environment"]["CLASSPATH"],
            ])
            cmd_args = [
                "java", "-cp", class_path,
                '-Dzookeeper.log.file=logs/%s.log' % name,
                self.zk_config["Environment"]["ZOOMAIN"], cfg_path,
            ]
            entries.append((name, cmd_args))
        return entries

    def _write_ad_conf(self, topo_id, entries):
        config = configparser.ConfigParser(interpolation=None)
        names = []
        for name, entry in sorted(entries, key=lambda x: x[0]):
            names.append(name)
            config["program:%s" % name] = self._common_entry(name, entry)
        config["group:ad%s" % topo_id] = {"programs": ",".join(names)}
        text = StringIO()
        config.write(text)
        conf_path = os.path.join(self.out_dir, topo_id.ISD(), SUPERVISOR_DIR,
                                 "%s.conf" % topo_id.ISD_AD())
        write_file(conf_path, text.getvalue())

    def _get_path(self, topo_id, subdir, suffix):
        return os.path.join(self.out_dir, topo_id.ISD(),
                            subdir, "%s.%s" % (topo_id.ISD_AD(), suffix))

    def _topo_path(self, topo_id):
        return self._get_path(topo_id, TOPO_DIR, "json")

    def _conf_path(self, topo_id):
        return self._get_path(topo_id, CONF_DIR, "conf")

    def _path_policy_path(self, topo_id):
        return self._get_path(topo_id, PATH_POL_DIR, "json")

    def _trc_path(self, topo_id):
        return get_trc_file_path(topo_id.isd, topo_id.ad, topo_id.isd,
                                 INITIAL_TRC_VERSION, isd_dir=self.out_dir)

    def _common_entry(self, name, cmd_args):
        return {
            'autostart': 'false',
            'autorestart': 'false',
            'redirect_stderr': 'true',
            'environment': 'PYTHONPATH=.',
            'stdout_logfile_maxbytes': 0,
            'stdout_logfile': "logs/%s.out" % name,
            'startretries': 0,
            'startsecs': 5,
            'command': " ".join(['"%s"' % arg for arg in cmd_args]),
        }


class SimulatorGenerator(SupervisorGenerator):
    def __init__(self, out_dir, topo_dicts):
        self.out_dir = out_dir
        self.topo_dicts = topo_dicts
        self.sim_conf = StringIO()

    def generate(self):
        super().generate()
        self._write_run_script()
        self._write_sim_conf()

    def _zk_entries(self, topo_id):
        # No zookeeper service
        return []

    def _write_run_script(self):
        file_path = os.path.join(self.out_dir, SIM_DIR, 'run.sh')
        text = StringIO()
        text.write(
            '#!/bin/bash\n\n'
            'exec sim_test.py gen/SIM/sim.conf 100.\n')
        write_file(file_path, text.getvalue())

    def _write_ad_conf(self, topo_id, entries):
        for name, entry in sorted(entries, key=lambda x: x[0]):
            if not name.endswith("-1"):
                # Only one server per service
                continue
            self.sim_conf.write("%s\n" % " ".join([str(i) for i in entry[1:]]))

    def _write_sim_conf(self):
        conf = os.path.join(self.out_dir, SIM_DIR, SIM_CONF_FILE)
        write_file(conf, self.sim_conf.getvalue())


class ZKConfGenerator(object):
    def __init__(self, out_dir, zookeepers):
        self.out_dir = out_dir
        self.zookeepers = zookeepers
        self.datalog_dirs = []

    def generate(self):
        for topo_id, zks in self.zookeepers.items():
            self._write_ad_zk_configs(topo_id, zks)
        self._write_datalog_dirs()

    def _write_ad_zk_configs(self, topo_id, zks):
        # Build up server block
        servers = []
        for id_, zk in zks.items():
            servers.append("server.%s=%s:%d:%d" %
                           (id_, zk.addr, zk.leaderPort,
                            zk.electionPort))
        server_block = "\n".join(sorted(servers))
        base_dir = os.path.join(self.out_dir, topo_id.ISD(), ZOOKEEPER_DIR,
                                topo_id.ISD_AD())
        copy_file(DEFAULT_ZK_LOG4J, os.path.join(base_dir, "log4j.properties"))
        for id_, zk in zks.items():
            text = StringIO()
            datalog_dir = os.path.join(ZOOKEEPER_TMPFS_DIR, topo_id.ISD_AD(),
                                       id_)
            text.write("%s\n\n" % zk.config(
                os.path.join(base_dir, "data.%s" % id_),
                datalog_dir,
            ))
            text.write("%s\n" % server_block)
            write_file(os.path.join(base_dir, 'zoo.cfg.%s' % id_),
                       text.getvalue())
            write_file(os.path.join(base_dir, "data.%s" % id_, "myid"),
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


class TopoID(object):
    def __init__(self, id_str):
        self.isd, self.ad = id_str.split("-")

    @classmethod
    def from_values(cls, isd_id, ad_id):
        return cls("%s-%s" % (isd_id, ad_id))

    def ISD(self):
        return "ISD%s" % self.isd

    def ISD_AD(self):
        return "ISD%s-AD%s" % (self.isd, self.ad)

    def __lt__(self, other):
        return str(self) < str(other)

    def __str__(self):
        return "%s-%s" % (self.isd, self.ad)

    def __eq__(self, other):
        return self.isd == other.isd and self.ad == other.ad

    def __hash__(self):
        return hash(str(self))

    def __repr__(self):
        return "<TopoID: %s>" % self


class ZKTopo(object):
    def __init__(self, config, def_config):
        self.addr = None
        self.def_config = def_config
        self.manage = config.get("manage", False)
        if not self.manage:
            # A ZK we don't manage must have an assigned IP in the topology
            self.addr = ip_address(config["addr"])
        self.clientPort = config.get(
            "clientPort", def_config["clientPort"])
        self.leaderPort = config.get(
            "leaderPort", def_config["leaderPort"])
        self.electionPort = config.get(
            "electionPort", def_config["electionPort"])
        self.maxClientCnxns = config.get(
            "maxClientCnxns", def_config["maxClientCnxns"])

    def config(self, data_dir, data_log_dir):
        c = []
        for s in ('tickTime', 'initLimit', 'syncLimit', 'maxClientCnxns'):
            c.append("%s=%s" % (s, self.def_config[s]))
        c.append("dataDir=%s" % data_dir)
        c.append("dataLogDir=%s" % data_log_dir)
        c.append("clientPort=%s" % self.clientPort)
        c.append("clientPortAddress=%s" % self.addr)
        c.append("autopurge.purgeInterval=1")
        return "\n".join(c)


class SubnetGenerator(object):
    def __init__(self, network, def_prefix=DEFAULT_SUBNET_PREFIX):
        self._net = ip_network(network)
        if self._net.prefixlen >= def_prefix:
            logging.critical(
                "Network %s is too small to accomadate /%d subnets", self._net,
                def_prefix)
            sys.exit(1)
        self._subnets = self._net.subnets(new_prefix=def_prefix)
        self.link_network = next(self._subnets)
        self._map = defaultdict(lambda: AddressGenerator(next(self._subnets)))

    def get(self, location):
        try:
            return self._map[location]
        except StopIteration:
            logging.critical("Unable to allocate any more subnets from %s",
                             self._net)
            sys.exit(1)


class AddressGenerator(object):
    def __init__(self, subnet):
        self._subnet = subnet
        self._hosts = self._subnet.hosts()
        self._map = defaultdict(lambda: next(self._hosts))

    def get(self, id_):
        try:
            return self._map[id_], self._subnet
        except StopIteration:
            logging.critical("Unable to allocate any more addresses from %s",
                             self._subnet)
            sys.exit(1)


def _addr_type(addr):
    if addr.version == 4:
        return "IPV4"
    return "IPV6"


def main():
    """
    Main function.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--ad-config',
                        default=DEFAULT_ADCONFIGURATIONS_FILE,
                        help='AD configurations file')
    parser.add_argument('-s', '--sim', action='store_true', help='Simulator')
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
        args.output_dir, args.ad_config, args.path_policy, args.zk_config,
        args.network, args.sim, args.mininet)
    confgen.generate_all()


if __name__ == "__main__":
    main()
