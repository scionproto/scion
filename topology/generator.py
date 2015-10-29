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
import json
import logging
import math
import os
import sys
from collections import defaultdict
from io import StringIO
from ipaddress import ip_interface, ip_network
from string import Template

# External packages
from Crypto import Random
from dnslib.label import DNSLabel

# SCION
from lib.config import Config
from lib.crypto.asymcrypto import (
    generate_sign_keypair,
    sign,
)
from lib.crypto.certificate import Certificate, CertificateChain, TRC
from lib.defines import GEN_PATH, SCION_ROUTER_PORT
from lib.path_store import PathPolicy
from lib.topology import Topology
from lib.util import (
    copy_file,
    get_cert_chain_file_path,
    get_sig_key_file_path,
    get_trc_file_path,
    load_json_file,
    read_file,
    write_file,
)

DEFAULT_ADCONFIGURATIONS_FILE = "topology/ADConfigurations.json"
DEFAULT_PATH_POLICY_FILE = "topology/PathPolicy.json"
DEFAULT_ZK_CONFIG = "topology/Zookeeper.json"
DEFAULT_ZK_LOG4J = "topology/Zookeeper.log4j"

SIM_DIR = 'SIM'
SIM_CONF_FILE = 'sim.conf'
HOSTS_FILE = 'hosts'
NETWORKS_CONF = 'networks.conf'
SUPERVISOR_CONF = 'supervisord.conf'
COMMON_DIR = 'endhost'

ZOOKEEPER_HOST_TMPFS_DIR = "/run/shm/host-zk"
ZOOKEEPER_TMPFS_DIR = "/run/shm/scion-zk"

CORE_AD = 'CORE'

DEFAULT_BEACON_SERVERS = 1
DEFAULT_CERTIFICATE_SERVERS = 1
DEFAULT_PATH_SERVERS = 1
DEFAULT_DNS_SERVERS = 1
INITIAL_CERT_VERSION = 0
INITIAL_TRC_VERSION = 0
DEFAULT_DNS_DOMAIN = DNSLabel("scion")

DEFAULT_NETWORK = "127.0.0.0/8"
DEFAULT_MININET_NETWORK = "100.64.0.0/10"

SCION_SERVICE_NAMES = (
    "BeaconServers",
    "CertificateServers",
    "DNSServers",
    "EdgeRouters",
    "PathServers",
)


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
                val, self.zk_config)

    def generate_all(self):
        """
        Generate all needed files.
        """
        cert_files = self._generate_certs()
        topo_dicts, zookeepers, networks = self._generate_topology()
        self._generate_supervisor(topo_dicts, zookeepers)
        if self.is_sim:
            self._generate_sim_conf(topo_dicts)
        self._generate_zk_conf(zookeepers)
        self._write_cert_files(topo_dicts, cert_files)
        self._write_conf_policies(topo_dicts)
        self._write_networks_conf(networks)

    def _generate_certs(self):
        certgen = CertGenerator(self.ad_configs)
        return certgen.generate()

    def _generate_topology(self):
        topo_gen = TopoGenerator(self.ad_configs, self.out_dir, self.subnet_gen,
                                 self.zk_config, self.is_sim)
        return topo_gen.generate()

    def _generate_supervisor(self, topo_dicts, zookeepers):
        super_gen = SupervisorGenerator(self.out_dir, topo_dicts, zookeepers,
                                        self.zk_config, self.mininet)
        super_gen.generate()

    def _generate_sim_conf(self, topo_dicts):
        sim_gen = SimulatorGenerator(self.out_dir, topo_dicts)
        sim_gen.generate()

    def _generate_zk_conf(self, zookeepers):
        zk_gen = ZKConfGenerator(self.out_dir, zookeepers)
        zk_gen.generate()

    def _write_cert_files(self, topo_dicts, cert_files):
        for topo_id, ad_topo, base in _srv_iter(
                topo_dicts, self.out_dir, common=True):
            for path, value in cert_files[topo_id].items():
                write_file(os.path.join(base, path), value)

    def _write_conf_policies(self, topo_dicts):
        """
        Write AD configurations and path policies.
        """
        ad_confs = {}
        for topo_id, ad_topo, base in _srv_iter(
                topo_dicts, self.out_dir, common=True):
            ad_confs.setdefault(topo_id, "%s\n" % json.dumps(
                self._gen_ad_conf(ad_topo), sort_keys=True, indent=4))
            conf_file = os.path.join(base, "ad.conf")
            write_file(conf_file, ad_confs[topo_id])
            # Confirm that config parses cleanly.
            Config.from_file(conf_file)
            copy_file(self.path_policy_file,
                      os.path.join(base, "path_policy.conf"))
        # Confirm that parser actually works on path policy file
        PathPolicy.from_file(self.path_policy_file)

    def _gen_ad_conf(self, ad_topo):
        master_ad_key = base64.b64encode(Random.new().read(16))
        return {
            'MasterADKey': master_ad_key.decode("utf-8"),
            'RegisterTime': 10 if self.is_sim else 5,
            'PropagateTime': 10 if self.is_sim else 5,
            'MTU': 1500,
            'CertChainVersion': 0,
            # FIXME(kormat): This seems to always be true..:
            'RegisterPath': True if ad_topo["PathServers"] else False,
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
        write_file(os.path.join(self.out_dir, NETWORKS_CONF), text.getvalue())


class CertGenerator(object):
    def __init__(self, ad_configs):
        self.ad_configs = ad_configs
        self.sig_priv_keys = {}
        self.sig_pub_keys = {}
        self.enc_pub_keys = {}
        self.certs = {}
        self.trcs = {}
        self.cert_files = defaultdict(dict)

    def generate(self):
        self._self_sign_keys()
        self._iterate(self._gen_ad_keys)
        self._iterate(self._gen_ad_certs)
        self._build_chains()
        self._iterate(self._gen_trc_entry)
        self._iterate(self._sign_trc)
        self._iterate(self._gen_trc_files)
        return self.cert_files

    def _self_sign_keys(self):
        topo_id = TopoID.from_values(0, 0)
        self.sig_pub_keys[topo_id], self.sig_priv_keys[topo_id] = \
            generate_sign_keypair()
        self.enc_pub_keys[topo_id], _ = generate_sign_keypair()

    def _iterate(self, f):
        for isd_ad_id, ad_conf in self.ad_configs["ADs"].items():
            f(TopoID(isd_ad_id), ad_conf)

    def _gen_ad_keys(self, topo_id, ad_conf):
        sig_pub, sig_priv = generate_sign_keypair()
        enc_pub, enc_priv = generate_sign_keypair()
        self.sig_priv_keys[topo_id] = sig_priv
        self.sig_pub_keys[topo_id] = sig_pub
        self.enc_pub_keys[topo_id] = enc_pub
        sig_path = get_sig_key_file_path("")
        self.cert_files[topo_id][sig_path] = base64.b64encode(sig_priv).decode()

    def _gen_ad_certs(self, topo_id, ad_conf):
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
            cert_path = get_cert_chain_file_path(
                "", topo_id.isd, topo_id.ad, INITIAL_CERT_VERSION)
            self.cert_files[topo_id][cert_path] = \
                str(CertificateChain.from_values(chain))

    def _gen_trc_entry(self, topo_id, ad_conf):
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

    def _gen_trc_files(self, topo_id, _):
        trc_path = get_trc_file_path("", topo_id.isd, INITIAL_TRC_VERSION)
        self.cert_files[topo_id][trc_path] = str(self.trcs[topo_id.isd])


class TopoGenerator(object):
    def __init__(self, ad_configs, out_dir, subnet_gen, zk_config, is_sim):
        self.ad_configs = ad_configs
        self.out_dir = out_dir
        self.subnet_gen = subnet_gen
        self.zk_config = zk_config
        self.is_sim = is_sim
        self.topo_dicts = {}
        self.hosts = []
        self.zookeepers = defaultdict(dict)
        self.virt_addrs = set()

    def _reg_addr(self, topo_id, elem_id):
        subnet = self.subnet_gen.register(topo_id)
        return subnet.register(elem_id)

    def _reg_link_addrs(self, ad1, ad2):
        link_name = "%s<->%s" % tuple(sorted((ad1, ad2)))
        subnet = self.subnet_gen.register(link_name)
        ad1_name = "er%ser%s" % (ad1, ad2)
        ad2_name = "er%ser%s" % (ad2, ad1)
        return subnet.register(ad1_name), subnet.register(ad2_name)

    def _iterate(self, f):
        for isd_ad_id, ad_conf in self.ad_configs["ADs"].items():
            f(TopoID(isd_ad_id), ad_conf)

    def generate(self):
        self._iterate(self._generate_ad_topo)
        networks = self.subnet_gen.alloc_subnets()
        self._write_ad_topos()
        self._write_hosts()
        return self.topo_dicts, self.zookeepers, networks

    def _generate_ad_topo(self, topo_id, ad_conf):
        dns_domain = DNSLabel(ad_conf.get("dns_domain", DEFAULT_DNS_DOMAIN))
        dns_domain = dns_domain.add(
            "isd%s" % topo_id.isd).add("ad%s" % topo_id.ad)
        self.topo_dicts[topo_id] = {
            'Core': ad_conf['level'] == CORE_AD,
            'ISDID': int(topo_id.isd), 'ADID': int(topo_id.ad),
            'DnsDomain': str(dns_domain), 'Zookeepers': {},
        }
        for i in SCION_SERVICE_NAMES:
            self.topo_dicts[topo_id][i] = {}
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
            self.topo_dicts[topo_id][topo_key][elem_id] = {
                "Addr": self._reg_addr(topo_id, elem_id),
            }

    def _gen_hosts_entries(self, topo_id, dns_domain):
        for dns_srv in self.topo_dicts[topo_id]["DNSServers"].values():
            self.hosts.append((dns_srv["Addr"], dns_domain))

    def _gen_er_entries(self, topo_id, ad_conf):
        er_id = 1
        for remote, link_type in ad_conf["links"].items():
            self._gen_er_entry(topo_id, er_id, TopoID(remote), link_type)
            er_id += 1

    def _gen_er_entry(self, local, er_id, remote, remote_type):
        elem_id = "er%ser%s" % (local, remote)
        public_addr, remote_addr = self._reg_link_addrs(
            local, remote)
        self.topo_dicts[local]["EdgeRouters"][elem_id] = {
            'Addr': self._reg_addr(local, elem_id),
            'Interface': {
                'IFID': er_id,
                'NeighborISD': int(remote.isd),
                'NeighborAD': int(remote.ad),
                'NeighborType': remote_type,
                'Addr': public_addr,
                'ToAddr': remote_addr,
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

    def _write_ad_topos(self):
        for topo_id, ad_topo, base in _srv_iter(
                self.topo_dicts, self.out_dir, common=True):
            path = os.path.join(base, "topology.conf")
            contents = JSONAddrEncoder(sort_keys=True, indent=4).encode(
                self.topo_dicts[topo_id])
            write_file(path, contents)
            # Test if topo file parses cleanly
            Topology.from_file(path)

    def _write_hosts(self):
        text = StringIO()
        for intf, domain in self.hosts:
            text.write("%s\tds.%s\n" % (intf.ip, str(domain).rstrip(".")))
        hosts_path = os.path.join(self.out_dir, HOSTS_FILE)
        write_file(hosts_path, text.getvalue())


class SupervisorGenerator(object):
    def __init__(self, out_dir, topo_dicts, zookeepers, zk_config, mininet):
        self.out_dir = out_dir
        self.topo_dicts = topo_dicts
        self.zookeepers = zookeepers
        self.zk_config = zk_config
        self.mininet = mininet

    def generate(self):
        for topo_id, topo in self.topo_dicts.items():
            self._ad_conf(topo_id, topo)

    def _ad_conf(self, topo_id, topo):
        entries = []
        base = self._get_base_path(topo_id)
        for key, cmd in (
            ("BeaconServers", "beacon_server.py"),
            ("CertificateServers", "cert_server.py"),
            ("PathServers", "path_server.py"),
            ("DNSServers", "dns_server.py"),
            ("EdgeRouters", "router.py"),
        ):
            entries.extend(self._std_entries(topo, key, cmd, base))
        entries.extend(self._zk_entries(topo_id))
        self._write_ad_conf(topo_id, entries)

    def _std_entries(self, topo, topo_key, cmd, base):
        entries = []
        for elem in topo.get(topo_key, {}):
            conf_dir = os.path.join(base, elem)
            entries.append((elem, ["infrastructure/%s" % cmd, elem, conf_dir]))
        return entries

    def _zk_entries(self, topo_id):
        if topo_id not in self.zookeepers:
            return []
        entries = []
        for name, (_, zk) in self.zookeepers[topo_id].items():
            entries.append((name, zk.super_conf(topo_id, name, self.out_dir)))
        return entries

    def _write_ad_conf(self, topo_id, entries):
        config = configparser.ConfigParser(interpolation=None)
        names = []
        includes = []
        base = os.path.join(self.out_dir, topo_id.ISD(), topo_id.AD())
        for elem, entry in sorted(entries, key=lambda x: x[0]):
            names.append(elem)
            conf_path = os.path.join(base, elem, SUPERVISOR_CONF)
            includes.append(os.path.join(elem, SUPERVISOR_CONF))
            self._write_elem_conf(elem, entry, conf_path)
            if self.mininet:
                self._write_elem_mininet_conf(elem, conf_path)
        config["group:ad%s" % topo_id] = {"programs": ",".join(names)}
        text = StringIO()
        config.write(text)
        conf_path = os.path.join(self.out_dir, topo_id.ISD(), topo_id.AD(),
                                 SUPERVISOR_CONF)
        write_file(conf_path, text.getvalue())

    def _write_elem_conf(self, elem, entry, conf_path):
        config = configparser.ConfigParser(interpolation=None)
        config["program:%s" % elem] = self._common_entry(elem, entry)
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

    def _get_base_path(self, topo_id):
        return os.path.join(self.out_dir, topo_id.ISD(), topo_id.AD())

    def _common_entry(self, name, cmd_args):
        entry = {
            'autostart': 'false' if self.mininet else 'false',
            'autorestart': 'false',
            'redirect_stderr': 'true',
            'environment': 'PYTHONPATH=.',
            'stdout_logfile_maxbytes': 0,
            'stdout_logfile': "logs/%s.out" % name,
            'startretries': 0,
            'startsecs': 5,
            'command': " ".join(['"%s"' % arg for arg in cmd_args]),
        }
        if self.mininet:
            entry['autostart'] = 'true'
        return entry


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
        for id_, zk in zks.values():
            servers.append("server.%s=%s:%d:%d" %
                           (id_, zk.addr.ip, zk.leaderPort, zk.electionPort))
        server_block = "\n".join(sorted(servers))
        base_dir = os.path.join(self.out_dir, topo_id.ISD(), topo_id.AD())
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


class TopoID(object):
    def __init__(self, id_str):
        self.isd, self.ad = id_str.split("-")

    @classmethod
    def from_values(cls, isd_id, ad_id):
        return cls("%s-%s" % (isd_id, ad_id))

    def ISD(self):
        return "ISD%s" % self.isd

    def AD(self):
        return "AD%s" % self.ad

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
        base_dir = os.path.join(out_dir, topo_id.ISD(), topo_id.AD(), name)
        cfg_path = os.path.join(base_dir, "zoo.cfg")
        class_path = ":".join([
            base_dir, self.zk_config["Environment"]["CLASSPATH"],
        ])
        return [
            "java", "-cp", class_path,
            '-Dzookeeper.log.file=logs/%s.log' % name,
            self.zk_config["Environment"]["ZOOMAIN"], cfg_path,
        ]


class JSONAddrEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, AddressProxy):
            return str(o)
        else:
            return super().default(o)


class SubnetGenerator(object):
    def __init__(self, network):
        self._net = ip_network(network)
        if "/" not in network:
            logging.critical("No prefix length specified for network '%s'",
                             network)
            sys.exit(1)
        self._subnets = defaultdict(lambda: AddressGenerator())

    def register(self, location):
        return self._subnets[location]

    def alloc_subnets(self):
        allocations = defaultdict(list)
        # Initialise the allocations with the supplied network
        allocations[self._net.prefixlen].append(self._net)
        max_prefix = self._net.max_prefixlen
        networks = {}
        for subnet in self._subnets.values():
            # Figure out what size subnet we need. Add 2 to the subnet size to
            # cover the network and broadcast addresses.
            req_prefix = max_prefix - math.ceil(math.log2(len(subnet) + 2))
            # Search all subnets from that size upwards
            for prefix in range(req_prefix, -1, -1):
                if not allocations[prefix]:
                    # No subnets available at this size
                    continue
                alloc = allocations[prefix].pop()
                # Carve out subnet of the required size
                new_net = next(alloc.subnets(new_prefix=req_prefix))
                logging.debug("Allocating %s from %s for subnet size %d" %
                              (new_net, alloc, len(subnet)))
                networks[new_net] = subnet.alloc_addrs(new_net)
                # Repopulate the allocations list with the left-over space
                for net in alloc.address_exclude(new_net):
                    allocations[net.prefixlen].append(net)
                break
            else:
                logging.critical("Unable to allocate /%d subnet" % req_prefix)
                sys.exit(1)
        return networks


class AddressGenerator(object):
    def __init__(self):
        self._addrs = defaultdict(lambda: AddressProxy())

    def register(self, id_):
        return self._addrs[id_]

    def alloc_addrs(self, subnet):
        hosts = subnet.hosts()
        interfaces = {}
        for elem, proxy in self._addrs.items():
            intf = ip_interface("%s/%s" % (next(hosts), subnet.prefixlen))
            interfaces[elem] = intf
            proxy.set_intf(intf)
        return interfaces

    def __len__(self):
        return len(self._addrs)


class AddressProxy(object):
    def __init__(self):
        self._intf = None
        self.ip = None

    def set_intf(self, intf):
        self._intf = intf
        self.ip = self._intf.ip

    def __str__(self):
        return str(self._intf)


def _srv_iter(topo_dicts, out_dir, common=False):
    for topo_id, ad_topo in topo_dicts.items():
        base = os.path.join(out_dir, topo_id.ISD(), topo_id.AD())
        for service in SCION_SERVICE_NAMES:
            for elem in ad_topo[service]:
                yield topo_id, ad_topo, os.path.join(base, elem)
        if common:
            yield topo_id, ad_topo, os.path.join(base, COMMON_DIR)


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
