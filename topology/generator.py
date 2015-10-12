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
import shutil
import sys
from collections import defaultdict
from io import StringIO
from ipaddress import ip_network
from tempfile import mkdtemp

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
from lib.defines import TOPOLOGY_PATH, SCION_ROUTER_PORT
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

DEFAULT_ADCONFIGURATIONS_FILE = os.path.join(TOPOLOGY_PATH,
                                             'ADConfigurations.json')
DEFAULT_PATH_POLICY_FILE = os.path.join(TOPOLOGY_PATH, 'PathPolicy.json')
DEFAULT_ZK_CONFIG = os.path.join(TOPOLOGY_PATH, "Zookeeper.json")
DEFAULT_ZK_LOG4J = os.path.join(TOPOLOGY_PATH, "Zookeeper.log4j")

SCRIPTS_DIR = 'topology'
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

ZOOKEEPER_DIR = 'zookeeper'
ZOOKEEPER_CFG = "zoo.cfg"
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
ISD_AD_ID_DIVISOR = '-'
DEFAULT_DNS_DOMAIN = DNSLabel("scion")

DEFAULT_NETWORK = "127.0.0.0/8"
DEFAULT_SUBNET_PREFIX = 27


class ConfigGenerator(object):
    """
    Configuration and/or topology generator.
    """
    def __init__(self, out_dir=TOPOLOGY_PATH,
                 adconfigurations_file=DEFAULT_ADCONFIGURATIONS_FILE,
                 path_policy_file=DEFAULT_PATH_POLICY_FILE,
                 zk_config_file=DEFAULT_ZK_CONFIG, network=None,
                 is_sim=False):
        """
        Initialize an instance of the class ConfigGenerator.

        :param string out_dir: path to the topology folder.
        :param string adconfigurations_file: path to ADConfigurations.json
        :param string path_policy_file: path to PathPolicy.json
        :param string zk_config_file: path to Zookeeper.json
        :param string network:
            Network to create subnets in, of the form x.x.x.x/y
        :param bool is_sim: Generate conf files for the Simulator
        """
        if not os.path.isdir(out_dir):
            logging.error(out_dir + " output directory missing")
            sys.exit()
        self.out_dir = out_dir
        self.ad_configs = load_json_file(adconfigurations_file)
        self.zk_config = load_json_file(zk_config_file)
        self.path_policy_file = path_policy_file
        self.is_sim = is_sim
        self.default_zookeepers = {}
        self._read_defaults(network)

    def _read_defaults(self, network):
        """
        Configure default network and ZooKeeper setup.
        """
        defaults = self.ad_configs.get("defaults", {})
        if network:
            def_network = network
        else:
            def_network = defaults.get("subnet", DEFAULT_NETWORK)
        self.subnet_gen = SubnetGenerator(def_network)
        for key, val in defaults.get("zookeepers", {}).items():
            self.default_zookeepers[key] = ZKTopo(
                val, self.zk_config["Default"])

    def generate_all(self):
        """
        Generate all needed files.
        """
        self._delete_directories()
        keys = self._write_keys_certs()
        self._write_conf_files()
        self._write_path_policy_files()
        self._write_topo_files()
        if self.is_sim:
            self._write_sim_run_preamble()
            self._write_sim_file()
        self._write_trc_files(self.ad_configs, keys)

    def _path_gen(self, isd_id, ad_id, subdir, suffix, abs_=True):
        """
        Generate a path to an output file.
        """
        if abs_:
            parts = [self.out_dir]
        else:
            parts = ["..", SCRIPTS_DIR]
        parts.append("ISD%s" % isd_id)
        parts.append(subdir)
        parts.append("ISD%s-AD%s%s" % (isd_id, ad_id, suffix))
        return os.path.join(*parts)

    def _trc_path_gen(self, isd_id, ad_id):
        """
        Generate a path to a TRC file.
        """
        trc_file_abs = get_trc_file_path(
            isd_id, ad_id, isd_id, INITIAL_TRC_VERSION, isd_dir=self.out_dir)
        return os.path.join('..', SCRIPTS_DIR,
                            os.path.relpath(trc_file_abs, self.out_dir))

    def _get_addr(self, isd_id, ad_id, elem_type, elem_id):
        """
        Get an address for an element, assigning a new address if necessary.
        """
        addr_gen = self.subnet_gen.get((isd_id, ad_id))
        return addr_gen.get((isd_id, ad_id, elem_type, elem_id))

    def _zk_path_dict(self, isd_id, ad_id, zk_id):
        """
        Generate paths needed for ZooKeeper configs.
        """
        def abs_rel(*paths):
            return os.path.join(self.out_dir, *paths), \
                os.path.join('..', SCRIPTS_DIR, *paths)
        isd_str = "ISD{}".format(isd_id)
        isd_ad_str = "ISD{}-AD{}".format(isd_id, ad_id)
        p = {}
        p['base_dir_tail'] = os.path.join(isd_str, ZOOKEEPER_DIR, isd_ad_str)
        p['base_dir_abs'], p['base_dir_rel'] = abs_rel(p['base_dir_tail'])
        p['data_dir_abs'], p['data_dir_rel'] = abs_rel(p['base_dir_tail'],
                                                       'data.%s' % zk_id)
        p['datalog_dir_abs'] = os.path.join(ZOOKEEPER_TMPFS_DIR, isd_ad_str,
                                            str(zk_id))
        p['datalog_script_abs'] = os.path.join(p['base_dir_abs'],
                                               "datalog.%s.sh" % zk_id)
        p['cfg_abs'], p['cfg_rel'] = abs_rel(p['base_dir_tail'],
                                             'zoo.cfg.%s' % zk_id)
        p['myid_abs'] = os.path.join(p['data_dir_abs'], 'myid')
        p['log4j_abs'] = os.path.join(p['base_dir_abs'], 'log4j.properties')
        return p

    def _delete_directories(self):
        """
        Delete any ISD* directories if present.
        """
        _, dirs, _ = next(os.walk(self.out_dir))
        for name in dirs:
            if name.startswith('ISD'):
                shutil.rmtree(os.path.join(self.out_dir, name))
            if name.startswith('SIM'):
                shutil.rmtree(os.path.join(self.out_dir, name))

    def _write_keys_certs(self):
        """
        Generate the AD certificates and keys and store them into separate
        files.

        :returns: the signature and encryption keys.
        :rtype: dict
        """
        sig_priv_keys = {}
        sig_pub_keys = {}
        enc_pub_keys = {}
        for isd_ad_id in self.ad_configs["ADs"]:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            sig_key_file = get_sig_key_file_path(isd_id, ad_id,
                                                 isd_dir=self.out_dir)
            enc_key_file = get_enc_key_file_path(isd_id, ad_id,
                                                 isd_dir=self.out_dir)
            (sig_pub, sig_priv) = generate_signature_keypair()
            (enc_pub, enc_priv) = generate_cryptobox_keypair()
            sig_priv_keys[isd_ad_id] = sig_priv
            sig_pub_keys[isd_ad_id] = sig_pub
            enc_pub_keys[isd_ad_id] = enc_pub
            sig_priv = base64.b64encode(sig_priv).decode('utf-8')
            enc_priv = base64.b64encode(enc_priv).decode('utf-8')
            write_file(sig_key_file, sig_priv)
            write_file(enc_key_file, enc_priv)

        # Generate keys for self-signing
        self_sign_id = ISD_AD_ID_DIVISOR.join(['0', '0'])
        (sig_pub, sig_priv) = generate_signature_keypair()
        (enc_pub, enc_priv) = generate_cryptobox_keypair()
        sig_priv_keys[self_sign_id] = sig_priv
        sig_pub_keys[self_sign_id] = sig_pub
        enc_pub_keys[self_sign_id] = enc_pub

        certs = {}
        for isd_ad_id, ad_config in self.ad_configs["ADs"].items():
            if ad_config['level'] == CORE_AD:
                continue
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            if 'cert_issuer' not in ad_config:
                logging.warning("No 'cert_issuer' attribute for "
                                "a non-core AD: {}".format(isd_ad_id))
                ad_config['cert_issuer'] = self_sign_id
            iss_isd_ad_id = ad_config['cert_issuer']
            (iss_isd_id, iss_ad_id) = iss_isd_ad_id.split(ISD_AD_ID_DIVISOR)
            cert = Certificate.from_values(
                'ISD:' + isd_id + '-AD:' + ad_id,
                sig_pub_keys[isd_ad_id], enc_pub_keys[isd_ad_id],
                'ISD:' + iss_isd_id + '-AD:' + iss_ad_id,
                sig_priv_keys[iss_isd_ad_id], INITIAL_CERT_VERSION)
            certs['ISD:' + isd_id + '-AD:' + ad_id] = [cert]
        for subject in certs:
            index = 0
            while certs[subject][index].issuer in certs:
                certs[subject].append(certs[certs[subject][index].issuer][0])
                index += 1
        for subject in certs:
            chain = CertificateChain.from_values(certs[subject])
            cert_isd = int(subject[4:].split('-AD:')[0])
            cert_ad = int(subject[4:].split('-AD:')[1])
            cert_file = get_cert_chain_file_path(cert_isd, cert_ad, cert_isd,
                                                 cert_ad, INITIAL_CERT_VERSION,
                                                 isd_dir=self.out_dir)
            write_file(cert_file, str(chain))
            # Test if parser works
            CertificateChain(cert_file)
        return {'sig_priv_keys': sig_priv_keys,
                'sig_pub_keys': sig_pub_keys,
                'enc_pub_keys': enc_pub_keys}

    def _write_sim_run_preamble(self):
        file_path = os.path.join(self.out_dir, SIM_DIR, 'run.sh')
        text = StringIO()
        text.write('#!/bin/bash\n\n')
        text.write('sh -c "PYTHONPATH=../ python3 sim_test.py'
                   '../SIM/sim.conf 100."\n')
        write_file(file_path, text.getvalue())

    def _write_topo_files(self):
        """
        Generate the AD topologies and store them into files. Update the AD
        setup and supervisor files.

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict
        :param er_ip_addresses: the edge router IP addresses.
        :type er_ip_addresses: dict
        """
        isd_hosts = {}
        for isd_ad_id, ad_conf in self.ad_configs["ADs"].items():
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            if self.is_sim:
                number_bs = 1
            else:
                number_bs = ad_conf.get("beacon_servers",
                                        DEFAULT_BEACON_SERVERS)
            number_cs = ad_conf.get("certificate_servers",
                                    DEFAULT_CERTIFICATE_SERVERS)
            number_ps = ad_conf.get("path_servers", DEFAULT_PATH_SERVERS)
            number_ds = ad_conf.get("dns_servers", DEFAULT_DNS_SERVERS)
            dns_domain = DNSLabel(ad_conf.get("dns_domain", DEFAULT_DNS_DOMAIN))
            dns_domain = dns_domain.add("isd%s" % isd_id).add("ad%s" % ad_id)
            hosts = isd_hosts.setdefault(isd_id, StringIO())
            # Write beginning and general structure
            topo_dict = {
                'Core': ad_conf['level'] == CORE_AD,
                'ISDID': int(isd_id),
                'ADID': int(ad_id),
                'DnsDomain': str(dns_domain),
                'BeaconServers': {},
                'CertificateServers': {},
                'PathServers': {},
                'DNSServers': {},
                'EdgeRouters': {},
                'Zookeepers': {},
            }

            # Write Beacon Servers
            for b_server in range(1, number_bs + 1):
                addr = self._get_addr(isd_id, ad_id, "bs", b_server)
                topo_dict['BeaconServers'][b_server] = {
                    'AddrType': 'IPV4',
                    'Addr': str(addr),
                }
            # Write Certificate Servers
            for c_server in range(1, number_cs + 1):
                addr = self._get_addr(isd_id, ad_id, "cs", c_server)
                topo_dict['CertificateServers'][c_server] = {
                    'AddrType': 'IPV4',
                    'Addr': str(addr),
                }
            # Write Path Servers
            if (ad_conf['level'] != INTERMEDIATE_AD or
                    "path_servers" in ad_conf):
                for p_server in range(1, number_ps + 1):
                    addr = self._get_addr(isd_id, ad_id, "ps", p_server)
                    topo_dict['PathServers'][p_server] = {
                        'AddrType': 'IPV4',
                        'Addr': str(addr),
                    }
            # Write DNS Servrs
            for d_server in range(1, number_ds + 1):
                addr = self._get_addr(isd_id, ad_id, "ds", d_server)
                topo_dict['DNSServers'][d_server] = {
                    'AddrType': 'IPV4',
                    'Addr': str(addr),
                }
                hosts.write("%s\tds.%s\n" % (addr, str(dns_domain).rstrip(".")))
            # Write Edge Routers
            edge_router = 1
            for nbr_isd_ad_id, nbr_type in ad_conf.get("links", {}).items():
                nbr_isd_id, nbr_ad_id = nbr_isd_ad_id.split(ISD_AD_ID_DIVISOR)
                local_ip = self._get_addr(isd_id, ad_id, "er", edge_router)
                public_ip = self._get_addr(
                    isd_id, ad_id, "er", (isd_id, ad_id, nbr_isd_id, nbr_ad_id))
                remote_ip = self._get_addr(
                    nbr_isd_id, nbr_ad_id, "er",
                    (nbr_isd_id, nbr_ad_id, isd_id, ad_id))
                if_id = edge_router
                topo_dict['EdgeRouters'][edge_router] = {
                    'AddrType': 'IPV4',
                    'Addr': str(local_ip),
                    'Interface': {
                        'IFID': if_id,
                        'NeighborISD': int(nbr_isd_id),
                        'NeighborAD': int(nbr_ad_id),
                        'NeighborType': nbr_type,
                        'AddrType': 'IPV4',
                        'Addr': str(public_ip),
                        'ToAddr': str(remote_ip),
                        'UdpPort': SCION_ROUTER_PORT,
                        'ToUdpPort': SCION_ROUTER_PORT,
                    }
                }
                edge_router += 1
            # Write Zookeepers
            zks = {}
            for key, val in ad_conf.get("zookeepers", {}).items():
                zks[key] = ZKTopo(val, self.zk_config["Default"])
            if not zks:
                zks = self.default_zookeepers
            for key, zk in zks.items():
                if not zk.addr:
                    # If there's no predefined addr, assign one.
                    zk.addr = str(self._get_addr(isd_id, ad_id, "zk", key))
                topo_dict['Zookeepers'][key] = zk.dict_()

            topo_file_abs = self._path_gen(isd_id, ad_id, TOPO_DIR, ".json")
            write_file(topo_file_abs,
                       json.dumps(topo_dict, sort_keys=True, indent=4))
            # Test if parser works
            Topology.from_file(topo_file_abs)

            self._write_derivatives(topo_dict)

        for isd_id, hosts in isd_hosts.items():
            hosts_path = os.path.join(self.out_dir, "ISD%s" % isd_id,
                                      HOSTS_FILE)
            write_file(hosts_path, hosts.getvalue())

    def _write_derivatives(self, topo_dict):
        """
        Write files, derived from the topology: supervisor configuration,
        setup files.

        :param topo_dict: topology dictionary of a SCION AD
        :type topo_dict: dict
        :param kwargs: misc arguments
        :type kwargs: dict
        :return:
        """
        self._write_supervisor_config(topo_dict)
        self._write_zookeeper_config(topo_dict)

    def _write_zookeeper_config(self, topo_dict):
        """
        Generate the AD Zookeeper configurations.

        :param topo_dict: topology dictionary of a SCION AD.
        :type topo_dict: dict
        """
        isd_id, ad_id = topo_dict['ISDID'], topo_dict['ADID']

        # Build up server block
        servers = []
        for zk_id, zk_dict in topo_dict['Zookeepers'].items():
            servers.append("server.%s=%s:%d:%d" %
                           (zk_id, zk_dict['Addr'], zk_dict['LeaderPort'],
                            zk_dict['ElectionPort']))
        server_block = "\n".join(sorted(servers))

        for zk_id, zk_dict in topo_dict['Zookeepers'].items():
            if not zk_dict.get("Manage", False):
                # We don't manage this zookeeper instance, so no need to
                # write configs for it.
                continue
            paths = self._zk_path_dict(isd_id, ad_id, zk_id)
            copy_file(DEFAULT_ZK_LOG4J, paths['log4j_abs'])
            text = StringIO()
            for s in ['tickTime', 'initLimit', 'syncLimit']:
                text.write("%s=%s\n" % (s, self.zk_config["Default"][s]))
            text.write("dataDir=%s\n" % paths['data_dir_rel'])
            text.write("dataLogDir=%s\n" % paths['datalog_dir_abs'])
            text.write("clientPort=%d\n" % zk_dict["ClientPort"])
            text.write("clientPortAddress=%s\n" % zk_dict["Addr"])
            text.write("maxClientCnxns=%s\n" % zk_dict["MaxClientCnxns"])
            text.write("autopurge.purgeInterval=1\n")
            text.write("%s\n" % server_block)
            write_file(paths['cfg_abs'], text.getvalue())
            write_file(paths['myid_abs'], "%s\n" % zk_id)
            write_file(paths['datalog_script_abs'],
                       "#!/bin/bash\n"
                       "mkdir -p %s\n" % paths['datalog_dir_abs'])

    def _write_sim_file(self):
        """
        Writing into sim.conf file

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict
        """
        text = StringIO()
        for isd_ad_id, ad_conf in self.ad_configs["ADs"].items():
            isd_id, ad_id = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            if ad_conf['level'] == CORE_AD:
                element_location = "core"
            else:
                element_location = "local"

            topo_file = self._path_gen(isd_id, ad_id, TOPO_DIR, ".json", False)
            conf_file = self._path_gen(isd_id, ad_id, CONF_DIR, ".conf", False)
            path_pol_file = self._path_gen(isd_id, ad_id, PATH_POL_DIR, ".json",
                                           False)
            trc_file = self._trc_path_gen(isd_id, ad_id)

            # Since we are running a simulator
            number_bs = 1
            number_cs = ad_conf.get("certificate_servers",
                                    DEFAULT_CERTIFICATE_SERVERS)
            number_ps = ad_conf.get("path_servers", DEFAULT_PATH_SERVERS)

            # Beacon Servers
            for b_server in range(1, number_bs + 1):
                element_name = 'bs{}-{}-{}'.format(isd_id, ad_id, b_server)
                text.write(' '.join([
                    'beacon_server', element_name, element_location,
                    str(b_server), topo_file, conf_file, path_pol_file]) + '\n')
            # Certificate Servers
            for c_server in range(1, number_cs + 1):
                element_name = 'cs{}-{}-{}'.format(isd_id, ad_id, c_server)
                text.write(' '.join([
                    'cert_server', element_name, str(c_server), topo_file,
                    conf_file, trc_file]) + '\n')
            # Path Servers
            if (ad_conf['level'] != INTERMEDIATE_AD or
                    "path_servers" in ad_conf):
                for p_server in range(1, number_ps + 1):
                    element_name = 'ps{}-{}-{}'.format(isd_id, ad_id, p_server)
                    text.write(' '.join([
                        'path_server', element_name, element_location,
                        str(p_server), topo_file, conf_file]) + '\n')
            # Edge Routers
            edge_router = 1
            for nbr_isd_ad_id in ad_conf.get("links", []):
                nbr_isd_id, nbr_ad_id = nbr_isd_ad_id.split(ISD_AD_ID_DIVISOR)
                element_name = 'er{}-{}er{}-{}'.format(isd_id, ad_id,
                                                       nbr_isd_id, nbr_ad_id)
                text.write(' '.join([
                    'router', element_name,
                    str(edge_router), topo_file, conf_file]) + '\n')
                edge_router += 1
        sim_file = os.path.join(self.out_dir, SIM_DIR, SIM_CONF_FILE)
        write_file(sim_file, text.getvalue())

    def _get_typed_elements(self, topo_dict):
        """
        Generator which iterates over all the elements in the topology
        supplemented with the corresponding type label.

        :param topo_dict: topology dictionary of a SCION AD.
        :type topo_dict: dict
        """
        element_types = ['BeaconServers', 'CertificateServers',
                         'PathServers', 'DNSServers', 'EdgeRouters',
                         'Zookeepers']
        for element_type in element_types:
            for element_num, element_dict in topo_dict[element_type].items():
                yield (element_num, element_dict, element_type)

    def _write_supervisor_config(self, topo_dict):
        """
        Generate the AD supervisor configuration and store it into a file.

        :param topo_dict: topology dictionary of a SCION AD.
        :type topo_dict: dict
        """
        supervisor_common = {
            'autostart': 'false',
            'autorestart': 'false',
            'redirect_stderr': 'true',
            'environment': 'PYTHONPATH=..',
            'stdout_logfile_maxbytes': '0',
            'startretries': '0',
        }

        program_group = []
        supervisor_config = configparser.ConfigParser(interpolation=None)

        isd_id, ad_id = topo_dict['ISDID'], topo_dict['ADID']
        dns_domain = topo_dict['DnsDomain']
        topo_file = self._path_gen(isd_id, ad_id, TOPO_DIR, ".json", False)
        conf_file = self._path_gen(isd_id, ad_id, CONF_DIR, ".conf", False)
        path_pol_file = self._path_gen(isd_id, ad_id, PATH_POL_DIR, ".json",
                                       False)
        trc_file = self._trc_path_gen(isd_id, ad_id)

        for (num, element_dict, element_type) \
                in self._get_typed_elements(topo_dict):
            element_location = 'core' if topo_dict['Core'] else 'local'
            server_config = supervisor_common.copy()
            if element_type == 'BeaconServers':
                element_name = 'bs{}-{}-{}'.format(isd_id, ad_id, num)
                cmd_args = ['beacon_server.py', element_location, num,
                            topo_file, conf_file, path_pol_file,
                            '../logs/{}.log'.format(element_name)]
            elif element_type == 'CertificateServers':
                element_name = 'cs{}-{}-{}'.format(isd_id, ad_id, num)
                cmd_args = ['cert_server.py', num,
                            topo_file, conf_file, trc_file,
                            '../logs/{}.log'.format(element_name)]
            elif element_type == 'PathServers':
                element_name = 'ps{}-{}-{}'.format(isd_id, ad_id, num)
                cmd_args = ['path_server.py', element_location, num,
                            topo_file, conf_file,
                            '../logs/{}.log'.format(element_name)]
            elif element_type == 'DNSServers':
                element_name = 'ds{}-{}-{}'.format(isd_id, ad_id, num)
                cmd_args = ['dns_server.py', num, str(dns_domain), topo_file,
                            '../logs/{}.log'.format(element_name)]
            elif element_type == 'EdgeRouters':
                interface_dict = element_dict['Interface']
                nbr_isd_id = interface_dict['NeighborISD']
                nbr_ad_id = interface_dict['NeighborAD']
                element_name = 'er{}-{}er{}-{}'.format(isd_id, ad_id,
                                                       nbr_isd_id, nbr_ad_id)
                cmd_args = ['router.py', num, topo_file, conf_file,
                            '../logs/{}.log'.format(element_name)]
            elif element_type == 'Zookeepers':
                if not element_dict['Manage']:
                    continue
                element_name = 'zk{}-{}-{}'.format(isd_id, ad_id, num)
                base_dir = self._path_gen(isd_id, ad_id, ZOOKEEPER_DIR, "",
                                          False)
                cfg_path = self._path_gen(isd_id, ad_id, ZOOKEEPER_DIR,
                                          "/zoo.cfg.%s" % num, False)
                class_path = ":".join([
                    base_dir, self.zk_config["Environment"]["CLASSPATH"],
                ])
                server_config['command'] = ' '.join([
                    '/usr/bin/java', '-cp', class_path,
                    '-Dzookeeper.log.file=../logs/{}.log'.format(element_name),
                    self.zk_config["Environment"]["ZOOMAIN"], cfg_path,
                ])
            else:
                assert False, 'Invalid element type'

            if 'command' not in server_config:
                server_config['command'] = ' '.join(
                    ['/usr/bin/python3'] +
                    ['"{}"'.format(arg) for arg in cmd_args])
            server_config['stdout_logfile'] = \
                '../logs/{}.out'.format(element_name)

            supervisor_config['program:' + element_name] = server_config
            program_group.append(element_name)

        group_header = "group:ad{}-{}".format(isd_id, ad_id)
        supervisor_config[group_header] = {'programs': ','.join(program_group)}

        # Write config
        text = StringIO()
        supervisor_config.write(text)
        super_config_path = self._path_gen(isd_id, ad_id, SUPERVISOR_DIR,
                                           ".conf")
        write_file(super_config_path, text.getvalue())

    def _write_conf_files(self):
        """
        Generate the AD configurations and store them into files.
        """
        for isd_ad_id, ad_conf in self.ad_configs["ADs"].items():
            isd_id, ad_id = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            conf_file = self._path_gen(isd_id, ad_id, CONF_DIR, ".conf")
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
            write_file(conf_file,
                       json.dumps(conf_dict, sort_keys=True, indent=4))
            # Test if parser works
            Config.from_file(conf_file)

    def _write_path_policy_files(self):
        """
        Generate the AD path policies and store them into files.
        """
        for isd_ad_id in self.ad_configs["ADs"]:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            new_path_pol_file = self._path_gen(
                isd_id, ad_id, PATH_POL_DIR, ".json")
            copy_file(self.path_policy_file, new_path_pol_file)
            # Test if parser works
            PathPolicy.from_file(new_path_pol_file)

    def _write_trc_files(self, ad_configs, keys):
        """
        Generate the ISD TRCs and store them into files.

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict
        :param keys: the signature and encryption keys.
        :type: dict
        """
        tmp_dir = mkdtemp(prefix="scion-generator.")
        for isd_ad_id, ad_conf in ad_configs["ADs"].items():
            if ad_conf['level'] != CORE_AD:
                continue
            isd_id, ad_id = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            trc_file = os.path.join(tmp_dir, 'ISD{}-V0.crt'.format(isd_id))
            # Create core certificate
            subject = 'ISD:' + isd_id + '-AD:' + ad_id
            cert = Certificate.from_values(
                subject,
                keys['sig_pub_keys'][isd_ad_id],
                keys['enc_pub_keys'][isd_ad_id],
                subject,
                keys['sig_priv_keys'][isd_ad_id],
                0)
            if os.path.exists(trc_file):
                trc = TRC(trc_file)
                trc.core_ads[subject] = cert
            else:
                core_isps = {'isp.com': 'isp.com_cert_base64'}
                root_cas = {'ca.com': 'ca.com_cert_base64'}
                core_ads = {subject: cert}
                registry_server_addr = 'isd_id-ad_id-ip_address'
                registry_server_cert = 'reg_server_cert_base64'
                root_dns_server_addr = 'isd_id-ad_id-ip_address'
                root_dns_server_cert = 'dns_server_cert_base64'
                trc_server_addr = 'isd_id-ad_id-ip_address'
                signatures = {}
                trc = TRC.from_values(
                    int(isd_id), 0, 1, 1, core_isps, root_cas,
                    core_ads, {}, registry_server_addr,
                    registry_server_cert, root_dns_server_addr,
                    root_dns_server_cert, trc_server_addr, signatures)
            write_file(trc_file, str(trc))
            # Test if parser works
            TRC(trc_file)

        for isd_ad_id, ad_conf in ad_configs["ADs"].items():
            if ad_conf['level'] != CORE_AD:
                continue
            isd_id, ad_id = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            trc_file = os.path.join(tmp_dir, 'ISD{}-V0.crt'.format(isd_id))
            subject = 'ISD:' + isd_id + '-AD:' + ad_id
            if os.path.exists(trc_file):
                trc = TRC(trc_file)
                data_to_sign = trc.__str__(with_signatures=False)
                data_to_sign = data_to_sign.encode('utf-8')
                sig = sign(data_to_sign, keys['sig_priv_keys'][isd_ad_id])
                trc.signatures[subject] = sig
                write_file(trc_file, str(trc))
                # Test if parser works
                TRC(trc_file)

        # Copy the created TRC files to every AD directory, then remove them
        for isd_ad_id in ad_configs["ADs"]:
            isd_id, ad_id = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            trc_file = os.path.join(tmp_dir, 'ISD{}-V0.crt'.format(isd_id))
            if os.path.exists(trc_file):
                dst_path = get_trc_file_path(isd_id, ad_id, isd_id, 0,
                                             isd_dir=self.out_dir)
                copy_file(trc_file, dst_path)
        shutil.rmtree(tmp_dir)


class ZKTopo(object):
    def __init__(self, config, def_config):
        self.addr = None
        self.manage = config.get("manage", False)
        if not self.manage:
            # A ZK we don't manage must have an assigned IP in the topology
            self.addr = config["addr"]
        self.clientPort = config.get(
            "client_port", int(def_config["clientPort"]))
        self.leaderPort = config.get(
            "leader_port", int(def_config["leaderPort"]))
        self.electionPort = config.get(
            "election_port", int(def_config["electionPort"]))
        self.maxClientCnxns = config.get(
            "max_client_cnxns", int(def_config["maxClientCnxns"]))

    def dict_(self):
        return {
            "Manage": self.manage,
            "Addr": self.addr,
            'AddrType': 'IPV4',
            "ClientPort": self.clientPort,
            "LeaderPort": self.leaderPort,
            "ElectionPort": self.electionPort,
            "MaxClientCnxns": self.maxClientCnxns,
        }


class SubnetGenerator(object):
    def __init__(self, network):
        self._net = ip_network(network)
        if self._net.prefixlen >= DEFAULT_SUBNET_PREFIX:
            logging.critical(
                "Network %s is too small to accomadate /%d subnets", self._net,
                DEFAULT_SUBNET_PREFIX)
            sys.exit(1)
        self._subnets = self._net.subnets(new_prefix=DEFAULT_SUBNET_PREFIX)
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
            return self._map[id_]
        except StopIteration:
            logging.critical("Unable to allocate any more addresses from %s",
                             self._subnet)
            sys.exit(1)


def main():
    """
    Main function.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--ad-config',
                        default=DEFAULT_ADCONFIGURATIONS_FILE,
                        help='AD configurations file')
    parser.add_argument('-s', '--sim',
                        action='store_true',
                        help='Simulator')
    parser.add_argument('-p', '--path-policy',
                        default=DEFAULT_PATH_POLICY_FILE,
                        help='Path policy file')
    parser.add_argument('-n', '--network',
                        help='Network to create subnets in (E.g. "127.0.0.0/8"')
    parser.add_argument('-o', '--output-dir',
                        default=TOPOLOGY_PATH,
                        help='Output directory')
    parser.add_argument('-z', '--zk-config',
                        default=DEFAULT_ZK_CONFIG,
                        help='Zookeeper configuration file')
    args = parser.parse_args()
    confgen = ConfigGenerator(args.output_dir, args.ad_config, args.path_policy,
                              args.zk_config, args.network, args.sim)
    confgen.generate_all()


if __name__ == "__main__":
    main()
