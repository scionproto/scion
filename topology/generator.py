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
from lib.defines import TOPOLOGY_PATH
from lib.path_store import PathPolicy
from lib.topology import Topology
from lib.util import (
    get_cert_chain_file_path,
    get_enc_key_file_path,
    get_sig_key_file_path,
    get_trc_file_path,
    write_file,
)

DEFAULT_ADCONFIGURATIONS_FILE = os.path.join(TOPOLOGY_PATH,
                                             'ADConfigurations.json')
DEFAULT_PATH_POLICY_FILE = os.path.join(TOPOLOGY_PATH, 'PathPolicy.json')

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

CORE_AD = 'CORE'
INTERMEDIATE_AD = 'INTERMEDIATE'
LEAF_AD = 'LEAF'

DEFAULT_BEACON_SERVERS = 1
DEFAULT_CERTIFICATE_SERVERS = 1
DEFAULT_PATH_SERVERS = 1
DEFAULT_DNS_SERVERS = 1
INITIAL_CERT_VERSION = 0
INITIAL_TRC_VERSION = 0
PORT = '50000'
ISD_AD_ID_DIVISOR = '-'
DEFAULT_DNS_DOMAIN = DNSLabel("scion")

DEFAULT_SUBNET = "127.0.0.0/8"
IP_ADDRESS_BASE = "127.0.0.1"


class ConfigGenerator(object):
    """
    Configuration and/or topology generator.
    """
    def __init__(self, out_dir=TOPOLOGY_PATH, subnet=DEFAULT_SUBNET,
                 next_ip_address=IP_ADDRESS_BASE, is_sim=False):
        """
        Initialize an instance of the class ConfigGenerator.

        :param out_dir: path to the topology folder.
        :type out_dir: string
        :param subnet: default subnet IP.
        :type subnet: string
        :param is_sim: Generate conf files for the Simulator
        :type is_sim: bool
        """
        if not os.path.isdir(out_dir):
            logging.error(out_dir + " output directory missing")
            sys.exit()
        self.out_dir = out_dir
        self.subnet = subnet
        self.next_ip_address = next_ip_address
        self.is_sim = is_sim

    def get_subnet_params(self, ad_config=None):
        """
        Return the first byte and the mask of the subnet.

        :param ad_config: AD configuration dictionary (optional)
        :type ad_config: dict

        :returns: the pair of the first byte and the mask
        :rtype: (str, str)
        """
        if ad_config and "subnet" in ad_config:
            subnet = ad_config["subnet"]
        else:
            subnet = self.subnet
        first_byte = subnet.split('.')[0]
        mask = subnet.split('/')[1]
        return first_byte, mask

    def path_dict(self, isd_id, ad_id):
        """
        Return a dictionary with the computed paths for a given AD.

        :param isd_id: ISD identifier.
        :type isd_id: int
        :param ad_id: AD identifier.
        :type ad_id: int

        :returns: the computed paths for a given AD.
        :rtype: dict
        """
        isd_name = 'ISD{}'.format(isd_id)
        file_no_ext = 'ISD:{}-AD:{}'.format(isd_id, ad_id)

        supervisor_file_abs = os.path.join(self.out_dir, isd_name,
                                           SUPERVISOR_DIR,
                                           file_no_ext + '.conf')

        topo_path_tail = os.path.join(isd_name, TOPO_DIR,
                                      file_no_ext + '.json')
        topo_file_abs = os.path.join(self.out_dir, topo_path_tail)
        topo_file_rel = os.path.join("..", SCRIPTS_DIR, topo_path_tail)

        conf_path_tail = os.path.join(isd_name, CONF_DIR,
                                      file_no_ext + '.conf')
        conf_file_abs = os.path.join(self.out_dir, conf_path_tail)
        conf_file_rel = os.path.join("..", SCRIPTS_DIR, conf_path_tail)

        trc_file_abs = get_trc_file_path(isd_id, ad_id, isd_id,
                                         INITIAL_TRC_VERSION,
                                         isd_dir=self.out_dir)
        trc_file_rel = os.path.join('..', SCRIPTS_DIR,
                                    os.path.relpath(trc_file_abs, self.out_dir))
        trc_temp_file = os.path.join(self.out_dir, isd_name,
                                     'ISD:{}-V:0.crt'.format(isd_id))

        path_pol_path_tail = os.path.join(isd_name, PATH_POL_DIR,
                                          file_no_ext + '.json')
        path_pol_file_abs = os.path.join(self.out_dir, path_pol_path_tail)
        path_pol_file_rel = os.path.join("..", SCRIPTS_DIR, path_pol_path_tail)
        return locals()

    def increment_address(self, ip_addr, mask, increment=1):
        """
        Increment an IP address value.

        :param ip_addr: the IP address to increment.
        :type ip_addr: str
        :param mask: subnet mask for the given IP address.
        :type mask: str
        :param increment: step the IP address must be incremented of.
        :type increment: int

        :returns: the incremented IP address. It fails if a broadcast address is
                  reached.
        :rtype: str
        """
        subnet = ip_network('{}/{}'.format(ip_addr, mask), strict=False)
        ip_addr_obj = ip_address(ip_addr) + increment
        if ip_addr_obj >= subnet.broadcast_address:
            logging.error("Reached a broadcast IP address: " + str(ip_addr_obj))
            sys.exit()
        return str(ip_addr_obj)

    def set_er_ip_addresses(self, ad_configs):
        """
        Set the IP addresses of all edge routers.

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict

        :returns: the edge router IP addresses.
        :rtype: dict
        """
        er_ip_addresses = {}
        for isd_ad_id in ad_configs:
            first_byte, mask = self.get_subnet_params(ad_configs[isd_ad_id])
            ip_address_loc = self.next_ip_address
            ip_address_pub = self.increment_address(ip_address_loc, mask)
            self.next_ip_address = \
                self.increment_address(self.next_ip_address, mask, 2)
            for link in ad_configs[isd_ad_id].get("links", []):
                er_ip_addresses[(isd_ad_id, link)] = (str(ip_address_loc),
                                                      str(ip_address_pub))
                ip_address_loc = self.next_ip_address
                ip_address_pub = \
                    self.increment_address(ip_address_loc, mask)
                self.next_ip_address = \
                    self.increment_address(self.next_ip_address, mask, 2)
        return er_ip_addresses

    def delete_directories(self):
        """
        Delete any ISD* directories if present.
        """
        _, dirs, _ = next(os.walk(self.out_dir))
        for name in dirs:
            if name.startswith('ISD'):
                shutil.rmtree(os.path.join(self.out_dir, name))
            if name.startswith('SIM'):
                shutil.rmtree(os.path.join(self.out_dir, name))

    def create_directories(self, ad_configs):
        """
        Create the ISD* directories and sub-directories, where all files used
        to run the SCION ADs are stored.

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict
        """
        for isd_ad_id in ad_configs:
            (isd_id, ad_id) = isd_ad_id.split('-')
            isd_name = 'ISD' + isd_id
            ad_name = 'AD' + ad_id
            cert_path = os.path.join(isd_name, CERT_DIR, ad_name)
            conf_path = os.path.join(isd_name, CONF_DIR)
            topo_path = os.path.join(isd_name, TOPO_DIR)
            sig_keys_path = os.path.join(isd_name, SIG_KEYS_DIR)
            enc_keys_path = os.path.join(isd_name, ENC_KEYS_DIR)
            path_pol_path = os.path.join(isd_name, PATH_POL_DIR)
            supervisor_path = os.path.join(isd_name, SUPERVISOR_DIR)
            paths = [cert_path, conf_path, topo_path, sig_keys_path,
                     enc_keys_path, path_pol_path, supervisor_path]
            for path in paths:
                full_path = os.path.join(self.out_dir, path)
                if not os.path.exists(full_path):
                    os.makedirs(full_path)
        if self.is_sim:
            sim_path = os.path.join(self.out_dir, 'SIM')
            if not os.path.exists(sim_path):
                os.makedirs(sim_path)

    def write_keys_certs(self, ad_configs):
        """
        Generate the AD certificates and keys and store them into separate
        files.

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict

        :returns: the signature and encryption keys.
        :rtype: dict
        """
        sig_priv_keys = {}
        sig_pub_keys = {}
        enc_pub_keys = {}
        for isd_ad_id in ad_configs:
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
        for isd_ad_id in ad_configs:
            if ad_configs[isd_ad_id]['level'] != CORE_AD:
                (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
                ad_config = ad_configs[isd_ad_id]
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

    def write_beginning_sim_run_files(self):
        file_path = os.path.join(self.out_dir, SIM_DIR, 'run.sh')
        with open(file_path, 'w') as fh:
            fh.write('#!/bin/bash\n\n')
            fh.write('sh -c "PYTHONPATH=../ python3 sim_test.py'
                     '../SIM/sim.conf 100."\n')

    def write_topo_files(self, ad_configs, er_ip_addresses):
        """
        Generate the AD topologies and store them into files. Update the AD
        setup and supervisor files.

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict
        :param er_ip_addresses: the edge router IP addresses.
        :type er_ip_addresses: dict
        """
        for isd_ad_id in ad_configs:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            is_core = (ad_configs[isd_ad_id]['level'] == CORE_AD)
            first_byte, mask = self.get_subnet_params(ad_configs[isd_ad_id])
            number_bs = ad_configs[isd_ad_id].get("beacon_servers",
                                                  DEFAULT_BEACON_SERVERS)
            if self.is_sim:
                number_bs = 1
            number_cs = ad_configs[isd_ad_id].get("certificate_servers",
                                                  DEFAULT_CERTIFICATE_SERVERS)
            number_ps = ad_configs[isd_ad_id].get("path_servers",
                                                  DEFAULT_PATH_SERVERS)
            number_ds = ad_configs[isd_ad_id].get("dns_servers",
                                                  DEFAULT_DNS_SERVERS)
            dns_domain = DNSLabel(ad_configs[isd_ad_id].get("dns_domain",
                                                            DEFAULT_DNS_DOMAIN))
            dns_domain = dns_domain.add("isd%s" % isd_id).add("ad%s" % ad_id)
            # Write beginning and general structure
            topo_dict = {'Core': 1 if is_core else 0,
                         'ISDID': int(isd_id),
                         'ADID': int(ad_id),
                         'DnsDomain': str(dns_domain),
                         'BeaconServers': {},
                         'CertificateServers': {},
                         'PathServers': {},
                         'DNSServers': {},
                         'EdgeRouters': {}}

            # Write Beacon Servers
            for b_server in range(1, number_bs + 1):
                topo_dict['BeaconServers'][b_server] = {
                    'AddrType': 'IPv4',
                    'Addr': self.next_ip_address
                }
                self.next_ip_address = \
                    self.increment_address(self.next_ip_address, mask)
            # Write Certificate Servers
            for c_server in range(1, number_cs + 1):
                topo_dict['CertificateServers'][c_server] = {
                    'AddrType': 'IPv4',
                    'Addr': self.next_ip_address
                }
                self.next_ip_address = \
                    self.increment_address(self.next_ip_address, mask)
            # Write Path Servers
            if (ad_configs[isd_ad_id]['level'] != INTERMEDIATE_AD or
                    "path_servers" in ad_configs[isd_ad_id]):
                for p_server in range(1, number_ps + 1):
                    topo_dict['PathServers'][p_server] = {
                        'AddrType': 'IPv4',
                        'Addr': self.next_ip_address
                    }
                    self.next_ip_address = \
                        self.increment_address(self.next_ip_address, mask)
            # Write DNS Servrs
            for d_server in range(1, number_ds + 1):
                topo_dict['DNSServers'][d_server] = {
                    'AddrType': 'IPv4',
                    'Addr': self.next_ip_address
                }
                self.next_ip_address = \
                    self.increment_address(self.next_ip_address, mask)
            # Write Edge Routers
            edge_router = 1
            for nbr_isd_ad_id in ad_configs[isd_ad_id].get("links", []):
                nbr_isd_id, nbr_ad_id = nbr_isd_ad_id.split(ISD_AD_ID_DIVISOR)
                ip_address_loc, ip_address_pub = \
                    er_ip_addresses[(isd_ad_id, nbr_isd_ad_id)]
                nbr_ip_address_pub = \
                    er_ip_addresses[(nbr_isd_ad_id, isd_ad_id)][1]
                nbr_type = ad_configs[isd_ad_id]["links"][nbr_isd_ad_id]
                if_id = edge_router
                topo_dict['EdgeRouters'][edge_router] = {
                    'AddrType': 'IPv4',
                    'Addr': ip_address_loc,
                    'Interface': {'IFID': if_id,
                                  'NeighborISD': int(nbr_isd_id),
                                  'NeighborAD': int(nbr_ad_id),
                                  'NeighborType': nbr_type,
                                  'AddrType': 'IPv4',
                                  'Addr': ip_address_pub,
                                  'ToAddr': nbr_ip_address_pub,
                                  'UdpPort': int(PORT),
                                  'ToUdpPort': int(PORT)}
                }
                edge_router += 1

            topo_file_abs = self.path_dict(isd_id, ad_id)['topo_file_abs']
            with open(topo_file_abs, 'w') as topo_fh:
                json.dump(topo_dict, topo_fh, sort_keys=True, indent=4)
            # Test if parser works
            Topology.from_file(topo_file_abs)

            self.write_derivatives(topo_dict, mask=mask)

    def write_derivatives(self, topo_dict, **kwargs):
        """
        Write files, derived from the topology: supervisor configuration,
        setup files.

        :param topo_dict: topology dictionary of a SCION AD
        :type topo_dict: dict
        :param kwargs: misc arguments
        :type kwargs: dict
        :return:
        """
        self.write_supervisor_config(topo_dict)

    def write_sim_file(self, ad_configs):
        """
        Writing into sim.conf file

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict
        """
        sim_file = os.path.join(self.out_dir, SIM_DIR, SIM_CONF_FILE)
        for isd_ad_id in ad_configs:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            is_core = (ad_configs[isd_ad_id]['level'] == CORE_AD)
            first_byte, mask = self.get_subnet_params(ad_configs[isd_ad_id])

            topo_file = self.path_dict(isd_id, ad_id)['topo_file_abs']
            path_pol_file = self.path_dict(isd_id, ad_id)['path_pol_file_abs']
            conf_file = self.path_dict(isd_id, ad_id)['conf_file_abs']
            trc_file = self.path_dict(isd_id, ad_id)['trc_file_abs']
            # Since we are running a simulator
            number_bs = 1
            number_cs = ad_configs[isd_ad_id].get("certificate_servers",
                                                  DEFAULT_CERTIFICATE_SERVERS)
            number_ps = ad_configs[isd_ad_id].get("path_servers",
                                                  DEFAULT_PATH_SERVERS)

            with open(sim_file, 'a') as sim_fh:
                # Beacon Servers
                for b_server in range(1, number_bs + 1):
                    sim_fh.write(' '.join([
                        'beacon_server', ('core' if is_core else 'local'),
                        str(b_server), topo_file,
                        conf_file, path_pol_file]) + '\n')
                # Certificate Servers
                for c_server in range(1, number_cs + 1):
                    sim_fh.write(' '.join([
                        'cert_server',
                        str(c_server), topo_file,
                        conf_file, trc_file]) + '\n')
                # Path Servers
                if (ad_configs[isd_ad_id]['level'] != INTERMEDIATE_AD or
                        "path_servers" in ad_configs[isd_ad_id]):
                    for p_server in range(1, number_ps + 1):
                        sim_fh.write(' '.join([
                            'path_server', ('core' if is_core else 'local'),
                            str(p_server), topo_file,
                            conf_file]) + '\n')
                # Edge Routers
                edge_router = 1
                for nbr_isd_ad_id in ad_configs[isd_ad_id].get("links", []):
                    sim_fh.write(' '.join([
                        'router',
                        str(edge_router), topo_file,
                        conf_file]) + '\n')
                    edge_router += 1

    def _get_typed_elements(self, topo_dict):
        """
        Generator which iterates over all the elements in the topology
        supplemented with the corresponding type label.

        :param topo_dict: topology dictionary of a SCION AD.
        :type topo_dict: dict
        """
        element_types = ['BeaconServers', 'CertificateServers',
                         'PathServers', 'DNSServers', 'EdgeRouters']
        for element_type in element_types:
            for element_num, element_dict in topo_dict[element_type].items():
                yield (element_num, element_dict, element_type)

    def write_supervisor_config(self, topo_dict):
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
        supervisor_config = configparser.ConfigParser()

        isd_id, ad_id = topo_dict['ISDID'], topo_dict['ADID']
        dns_domain = topo_dict['DnsDomain']
        p = self.path_dict(isd_id, ad_id)

        for (num, element_dict, element_type) \
                in self._get_typed_elements(topo_dict):
            element_location = 'core' if topo_dict['Core'] else 'local'
            if element_type == 'BeaconServers':
                element_name = 'bs{}-{}-{}'.format(isd_id, ad_id, num)
                cmd_args = ['beacon_server.py',
                            element_location,
                            num,
                            p['topo_file_rel'],
                            p['conf_file_rel'],
                            p['path_pol_file_rel']]

            elif element_type == 'CertificateServers':
                element_name = 'cs{}-{}-{}'.format(isd_id, ad_id, num)
                cmd_args = ['cert_server.py',
                            num,
                            p['topo_file_rel'],
                            p['conf_file_rel'],
                            p['trc_file_rel']]
            elif element_type == 'PathServers':
                element_name = 'ps{}-{}-{}'.format(isd_id, ad_id, num)
                cmd_args = ['path_server.py',
                            element_location,
                            num,
                            p['topo_file_rel'],
                            p['conf_file_rel']]
            elif element_type == 'DNSServers':
                element_name = 'ds{}-{}-{}'.format(isd_id, ad_id, num)
                cmd_args = ['dns_server.py',
                            num,
                            str(dns_domain),
                            p['topo_file_rel']]
            elif element_type == 'EdgeRouters':
                interface_dict = element_dict['Interface']
                nbr_isd_id = interface_dict['NeighborISD']
                nbr_ad_id = interface_dict['NeighborAD']
                element_name = 'er{}-{}er{}-{}'.format(isd_id, ad_id,
                                                       nbr_isd_id, nbr_ad_id)
                cmd_args = ['router.py',
                            num,
                            p['topo_file_rel'],
                            p['conf_file_rel']]
            else:
                assert False, 'Invalid element type'

            command_line = '/usr/bin/python3 '
            command_line += ' '.join(['"{}"'.format(arg) for arg in cmd_args])
            log_file = '../logs/{}.log'.format(element_name)
            server_config = supervisor_common.copy()
            server_config.update({'command': command_line,
                                  'stdout_logfile': log_file})

            supervisor_config['program:' + element_name] = server_config
            program_group.append(element_name)

        group_header = "group:ad{}-{}".format(isd_id, ad_id)
        supervisor_config[group_header] = {'programs': ','.join(program_group)}

        # Write config
        with open(p['supervisor_file_abs'], 'w') as conf_fh:
            supervisor_config.write(conf_fh)

    def write_conf_files(self, ad_configs):
        """
        Generate the AD configurations and store them into files.

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict
        """
        for isd_ad_id in ad_configs:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            file_name = 'ISD:{}-AD:{}.conf'.format(isd_id, ad_id)
            conf_file = os.path.join(self.out_dir, 'ISD' + isd_id,
                                     CONF_DIR, file_name)
            master_of_gen_key = base64.b64encode(Random.new().read(16))
            master_ad_key = base64.b64encode(Random.new().read(16))
            conf_dict = {'MasterOFGKey': master_of_gen_key.decode("utf-8"),
                         'MasterADKey': master_ad_key.decode("utf-8"),
                         'PCBQueueSize': 10,
                         'PSQueueSize': 10,
                         'NumRegisteredPaths': 10,
                         'NumShortestUPs': 3,
                         'RegisterTime': 5,
                         'PropagateTime': 5,
                         'ResetTime': 600,
                         'CertChainVersion': 0}
            if self.is_sim:
                conf_dict['PropagateTime'] = 10
                conf_dict['RegisterTime'] = 10
            if (ad_configs[isd_ad_id]['level'] != INTERMEDIATE_AD or
                    "path_servers" in ad_configs[isd_ad_id]):
                conf_dict['RegisterPath'] = 1
            else:
                conf_dict['RegisterPath'] = 0
            with open(conf_file, 'w') as conf_fh:
                json.dump(conf_dict, conf_fh, sort_keys=True, indent=4)
            # Test if parser works
            Config.from_file(conf_file)

    def write_path_pol_files(self, ad_configs, path_policy_file):
        """
        Generate the AD path policies and store them into files.

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict
        :param path_policy_file: path policy file path.
        :type path_policy_file: string
        """
        for isd_ad_id in ad_configs:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            path_dict = self.path_dict(isd_id, ad_id)
            new_path_pol_file = path_dict['path_pol_file_abs']
            shutil.copyfile(path_policy_file, new_path_pol_file)
            # Test if parser works
            PathPolicy.from_file(new_path_pol_file)

    def write_trc_files(self, ad_configs, keys):
        """
        Generate the ISD TRCs and store them into files.

        :param ad_configs: the configurations of all SCION ADs.
        :type ad_configs: dict
        :param keys: the signature and encryption keys.
        :type: dict
        """
        for isd_ad_id in ad_configs:
            if ad_configs[isd_ad_id]['level'] == CORE_AD:
                (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
                trc_file = self.path_dict(isd_id, ad_id)['trc_temp_file']
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

        for isd_ad_id in ad_configs:
            if ad_configs[isd_ad_id]['level'] == CORE_AD:
                (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
                trc_file = self.path_dict(isd_id, ad_id)['trc_temp_file']
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
        for isd_ad_id in ad_configs:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            trc_file = self.path_dict(isd_id, ad_id)['trc_temp_file']
            if os.path.exists(trc_file):
                dst_path = get_trc_file_path(isd_id, ad_id, isd_id, 0,
                                             isd_dir=self.out_dir)
                shutil.copyfile(trc_file, dst_path)
        for isd_ad_id in ad_configs:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            trc_file = self.path_dict(isd_id, ad_id)['trc_temp_file']
            if os.path.exists(trc_file):
                os.remove(trc_file)

    def generate_all(self, adconfigurations_file, path_policy_file):
        """
        Generate all needed files.

        :param adconfigurations_file: configuration file path.
        :type adconfigurations_file: string
        :param path_policy_file: path policy file path.
        :type path_policy_file: string
        """
        if not os.path.isfile(adconfigurations_file):
            logging.error(adconfigurations_file + " file missing.")
            sys.exit()
        if not os.path.isfile(path_policy_file):
            logging.error(path_policy_file + " file missing.")
            sys.exit()
        try:
            ad_configs = json.loads(open(adconfigurations_file).read())
        except (ValueError, KeyError, TypeError):
            logging.error(adconfigurations_file + ": JSON format error.")
            sys.exit()

        if "default_subnet" in ad_configs:
            self.subnet = ad_configs.pop("default_subnet")
        er_ip_addresses = self.set_er_ip_addresses(ad_configs)
        self.delete_directories()
        self.create_directories(ad_configs)
        keys = self.write_keys_certs(ad_configs)
        self.write_conf_files(ad_configs)
        self.write_path_pol_files(ad_configs, path_policy_file)
        self.write_topo_files(ad_configs, er_ip_addresses)
        if self.is_sim:
            self.write_beginning_sim_run_files()
            self.write_sim_file(ad_configs)
        self.write_trc_files(ad_configs, keys)


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
    parser.add_argument('-o', '--output-dir',
                        default=TOPOLOGY_PATH,
                        help='Output directory')
    args = parser.parse_args()
    generator = ConfigGenerator(os.path.abspath(args.output_dir),
                                is_sim=args.sim)
    generator.generate_all(args.ad_config, args.path_policy)


if __name__ == "__main__":
    main()
