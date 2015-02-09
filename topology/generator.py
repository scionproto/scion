# Copyright 2014 ETH Zurich

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
:mod:`generator` --- SCION topology generator
===========================================
"""

from lib.topology import Topology
from lib.config import Config
from lib.crypto.certificate import Certificate
from lib.crypto.trc import TRC
from lib.crypto.asymcrypto import *
import base64
import os
import shutil
import socket
import struct
import subprocess
import sys
import json
import logging


ADCONFIGURATIONS_FILE = 'ADConfigurations.json'

SCRIPTS_DIR = '/topology/'
CERT_DIR = '/certificates/'
CONF_DIR = '/configurations/'
TOPO_DIR = '/topologies/'
SIG_KEYS_DIR = '/signature_keys/'
ENC_KEYS_DIR = '/encryption_keys/'
SETUP_DIR = '/setup/'
RUN_DIR = '/run/'

CORE_AD = 'CORE'
INTERMEDIATE_AD = 'INTERMEDIATE'
LEAF_AD = 'LEAF'

DEFAULT_BEACON_SERVERS = 1
DEFAULT_CERTIFICATE_SERVERS = 1
DEFAULT_PATH_SERVERS = 1
PORT = '50000'
ISD_AD_ID_DIVISOR = '-'
BS_RANGE = '1'
CS_RANGE = '21'
PS_RANGE = '41'
ER_RANGE = '61'

default_subnet = "127.0.0.0/8"


def increment_address(ip_address, mask, increment=1):
    """
    Increment an IP address value.

    :param ip_address: the IP address to increment.
    :type ip_address: str
    :param mask: subnet mask for the given IP address.
    :type mask: str
    :param increment: step the IP address must be incremented of.
    :type increment: int
    :returns: the incremented IP address. It fails if a broadcast address is
              reached.
    :rtype: str
    """
    ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
    int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
    ip_address_int = ip2int(ip_address)
    ip_address_int += increment
    ip_address = int2ip(ip_address_int)
    bytes = ip_address.split('.')
    bits = ''.join([format(int(bytes[0]), '08b'), format(int(bytes[1]), '08b'),
                    format(int(bytes[2]), '08b'), format(int(bytes[3]), '08b')])
    if bits[int(mask):] == ('1' * (32 - int(mask))):
        logging.error("Reached a broadcast IP address: " + ip_address)
        sys.exit()
    return ip_address


def set_er_ip_addresses(AD_configs):
    """
    Set the IP addresses of all edge routers.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    :returns: the edge router IP addresses.
    :rtype: dict
    """
    er_ip_addresses = {}
    for isd_ad_id in AD_configs:
        if "subnet" in AD_configs[isd_ad_id]:
            first_byte = AD_configs[isd_ad_id]["subnet"].split('.')[0]
            mask = AD_configs[isd_ad_id]["subnet"].split('/')[1]
        else:
            first_byte = default_subnet.split('.')[0]
            mask = default_subnet.split('/')[1]
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        ip_address_loc = '.'.join([first_byte, isd_id, ad_id, ER_RANGE])
        ip_address_pub = \
            '.'.join([first_byte, isd_id, ad_id, str(int(ER_RANGE) + 1)])
        for link in AD_configs[isd_ad_id]["links"]:
            er_ip_addresses[(isd_ad_id, link)] = \
                (ip_address_loc, ip_address_pub)
            ip_address_loc = increment_address(ip_address_loc, mask, 2)
            ip_address_pub = increment_address(ip_address_pub, mask, 2)
    return er_ip_addresses


def delete_directories():
    """
    Delete any ISD* directories if present.
    """
    for root, dirs, files in os.walk('.'):
        for name in dirs:
            if name.startswith(('ISD')):
                shutil.rmtree(name)


def create_directories(AD_configs):
    """
    Create the ISD* directories and sub-directories, where all files used to run
    the SCION ADs are stored.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    """
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split('-')
        cert_path = 'ISD' + isd_id + CERT_DIR
        conf_path = 'ISD' + isd_id + CONF_DIR
        topo_path = 'ISD' + isd_id + TOPO_DIR
        sig_keys_path = 'ISD' + isd_id + SIG_KEYS_DIR
        enc_keys_path = 'ISD' + isd_id + ENC_KEYS_DIR
        setup_path =  'ISD' + isd_id + SETUP_DIR
        run_path = 'ISD' + isd_id + RUN_DIR
        if not os.path.exists(cert_path):
            os.makedirs(cert_path)
        if not os.path.exists(conf_path):
            os.makedirs(conf_path)
        if not os.path.exists(topo_path):
            os.makedirs(topo_path)
        if not os.path.exists(sig_keys_path):
            os.makedirs(sig_keys_path)
        if not os.path.exists(enc_keys_path):
            os.makedirs(enc_keys_path)
        if not os.path.exists(setup_path):
            os.makedirs(setup_path)
        if not os.path.exists(run_path):
            os.makedirs(run_path)


def write_keys_certs(AD_configs):
    """
    Generate the AD certificates and keys and store them into separate files.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    """
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id + '-V:' + '0'
        cert_file = 'ISD' + isd_id + CERT_DIR + file_name + '.crt'
        sig_key_file = 'ISD' + isd_id + SIG_KEYS_DIR + file_name + '.key'
        enc_key_file = 'ISD' + isd_id + ENC_KEYS_DIR + file_name + '.key'
        (sig_priv, sig_pub) = generate_signature_keypair()
        (enc_priv, enc_pub) = generate_cryptobox_keypair()
        cert = Certificate.from_values('ISD:' + isd_id + '-AD:' + ad_id,
            sig_pub, enc_pub, 'ISD:' + isd_id + '-AD:' + ad_id, sig_priv, 0)
        with open(sig_key_file, 'w') as key_fh:
            key_fh.write(str(sig_priv))
        with open(enc_key_file, 'w') as key_fh:
            key_fh.write(str(enc_priv))
        with open(cert_file, 'w') as cert_fh:
            cert_fh.write(str(cert))
        # Test if parser works
        cert = Certificate(cert_file)


def write_beginning_setup_run_files(AD_configs):
    """
    Create the beginning of the AD setup and run files.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    """
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id
        setup_file = 'ISD' + isd_id + SETUP_DIR + file_name + '.sh'
        run_file = 'ISD' + isd_id + RUN_DIR + file_name + '.sh'
        with open(setup_file, 'w') as setup_fh:
            setup_fh.write('#!/bin/bash\n\n')
        with open(run_file, 'w') as run_fh:
            run_fh.write('#!/bin/bash\n\n')


def write_topo_files(AD_configs, er_ip_addresses):
    """
    Generate the AD topologies and store them into files. Update the AD setup
    and run files.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    :param er_ip_addresses: the edge router IP addresses.
    :type er_ip_addresses: dict
    """
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id + '-V:' + '0'
        conf_file = 'ISD' + isd_id + CONF_DIR + file_name + '.conf'
        topo_file = 'ISD' + isd_id + TOPO_DIR + file_name + '.json'
        trc_file = 'ISD' + isd_id + '/' + 'ISD:' + isd_id + '-V:0.crt'
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id
        setup_file = 'ISD' + isd_id + SETUP_DIR + file_name + '.sh'
        run_file = 'ISD' + isd_id + RUN_DIR + file_name + '.sh'
        is_core = (AD_configs[isd_ad_id]['level'] == CORE_AD)
        if "subnet" in AD_configs[isd_ad_id]:
            first_byte = AD_configs[isd_ad_id]["subnet"].split('.')[0]
            mask = AD_configs[isd_ad_id]["subnet"].split('/')[1]
        else:
            first_byte = default_subnet.split('.')[0]
            mask = default_subnet.split('/')[1]
        if "beacon_servers" in AD_configs[isd_ad_id]:
            number_bs = AD_configs[isd_ad_id]["beacon_servers"]
        else:
            number_bs = DEFAULT_BEACON_SERVERS
        if "certificate_servers" in AD_configs[isd_ad_id]:
            number_cs = AD_configs[isd_ad_id]["certificate_servers"]
        else:
            number_cs = DEFAULT_CERTIFICATE_SERVERS
        if "path_servers" in AD_configs[isd_ad_id]:
            number_ps = AD_configs[isd_ad_id]["path_servers"]
        else:
            number_ps = DEFAULT_PATH_SERVERS
        # Write beginning and general structure
        topo_dict = {'Core': 1 if is_core else 0,
                     'ISDID': int(isd_id),
                     'ADID': int(ad_id),
                     'BeaconServers': {},
                     'CertificateServers': {},
                     'PathServers': {},
                     'EdgeRouters': {}}
        with open(setup_file, 'a') as setup_fh, open(run_file, 'a') as run_fh:
            # Write Beacon Servers
            ip_address = '.'.join([first_byte, isd_id, ad_id, BS_RANGE])
            for b_server in range(1, number_bs + 1):
                topo_dict['BeaconServers'][b_server] = {'AddrType': 'IPv4',
                                                        'Addr': ip_address}
                setup_fh.write('ip addr add ' + ip_address + '/' + mask +
                    ' dev lo\n')
                run_fh.write(''.join(['screen -d -m -S bs', isd_id, '-', ad_id,
                    '-', str(b_server), ' sh -c \"',
                    'PYTHONPATH=../ python3 beacon_server.py ',
                    ('core ' if is_core else 'local '), ip_address, ' ..',
                    SCRIPTS_DIR, topo_file, ' ..', SCRIPTS_DIR, conf_file,
                    '\"\n']))
                ip_address = increment_address(ip_address, mask)
            # Write Certificate Servers
            ip_address = '.'.join([first_byte, isd_id, ad_id, CS_RANGE])
            for c_server in range(1, number_cs + 1):
                topo_dict['CertificateServers'][c_server] = {'AddrType': 'IPv4',
                                                             'Addr': ip_address}
                setup_fh.write('ip addr add ' + ip_address + '/' + mask +
                    ' dev lo\n')
                run_fh.write(''.join(['screen -d -m -S cs', isd_id, '-', ad_id,
                    '-', str(c_server), ' sh -c \"',
                    "PYTHONPATH=../ python3 cert_server.py ", ip_address, ' ..',
                    SCRIPTS_DIR, topo_file, ' ..', SCRIPTS_DIR, conf_file,
                    ' ..', SCRIPTS_DIR, trc_file, '\"\n']))
                ip_address = increment_address(ip_address, mask)
            # Write Path Servers
            if (AD_configs[isd_ad_id]['level'] != INTERMEDIATE_AD or
                "path_servers" in AD_configs[isd_ad_id]):
                ip_address = '.'.join([first_byte, isd_id, ad_id, PS_RANGE])
                for p_server in range(1, number_ps + 1):
                    topo_dict['PathServers'][p_server] = {'AddrType': 'IPv4',
                                                          'Addr': ip_address}
                    setup_fh.write('ip addr add ' + ip_address + '/' + mask +
                        ' dev lo\n')
                    run_fh.write(''.join(['screen -d -m -S ps', isd_id, '-',
                        ad_id, '-', str(p_server), ' sh -c \"',
                        'PYTHONPATH=../ python3 path_server.py ',
                        ('core ' if is_core else 'local '), ip_address, ' ..',
                        SCRIPTS_DIR, topo_file, ' ..', SCRIPTS_DIR, conf_file,
                        '\"\n']))
                    ip_address = increment_address(ip_address, mask)
            # Write Edge Routers
            edge_router = 1
            for nbr_isd_ad_id in AD_configs[isd_ad_id]["links"]:
                (nbr_isd_id, nbr_ad_id) = nbr_isd_ad_id.split(ISD_AD_ID_DIVISOR)
                ip_address_loc = er_ip_addresses[(isd_ad_id, nbr_isd_ad_id)][0]
                ip_address_pub = er_ip_addresses[(isd_ad_id, nbr_isd_ad_id)][1]
                nbr_ip_address_pub = \
                    er_ip_addresses[(nbr_isd_ad_id, isd_ad_id)][1]
                nbr_type = AD_configs[isd_ad_id]["links"][nbr_isd_ad_id]
                if_id = str(255 + int(ad_id) + int(nbr_ad_id))
                topo_dict['EdgeRouters'][edge_router] = \
                    {'AddrType': 'IPv4',
                     'Addr': ip_address_loc,
                     'Interface': {'IFID': int(if_id),
                                   'NeighborISD': int(nbr_isd_id),
                                   'NeighborAD': int(nbr_ad_id),
                                   'NeighborType': nbr_type,
                                   'AddrType': 'IPv4',
                                   'Addr': ip_address_pub,
                                   'ToAddr': nbr_ip_address_pub,
                                   'UdpPort': int(PORT),
                                   'ToUdpPort': int(PORT)}}
                setup_fh.write('ip addr add ' + ip_address_loc + '/' + mask +
                    ' dev lo\n')
                run_fh.write(''.join(['screen -d -m -S er', isd_id, '-', ad_id,
                    'er', nbr_isd_id, '-', nbr_ad_id, ' sh -c \"',
                    'PYTHONPATH=../ python3 router.py ', ip_address_loc, ' ..',
                    SCRIPTS_DIR, topo_file, ' ..', SCRIPTS_DIR, conf_file,
                    '\"\n']))
                edge_router += 1
        with open(topo_file, 'w') as topo_fh:
            json.dump(topo_dict, topo_fh, sort_keys=True, indent=4)
        # Test if parser works
        topology = Topology(topo_file)


def write_conf_files(AD_configs):
    """
    Generate the AD configurations and store them into files.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    """
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id + '-V:' + '0'
        conf_file = 'ISD' + isd_id + CONF_DIR + file_name + '.conf'
        conf_dict = {'MasterOFGKey': 1234567890,
                     'MasterADKey': 1919191919,
                     'PCBQueueSize': 10,
                     'PSQueueSize': 10,
                     'NumRegisteredPaths': 10,
                     'NumShortestUPs': 3,
                     'RegisterTime': 5,
                     'PropagateTime': 5,
                     'ResetTime': 600}
        if (AD_configs[isd_ad_id]['level'] != INTERMEDIATE_AD or
            "path_servers" in AD_configs[isd_ad_id]):
            conf_dict['RegisterPath'] = 1
        else:
            conf_dict['RegisterPath'] = 0
        with open(conf_file, 'w') as conf_fh:
            json.dump(conf_dict, conf_fh, sort_keys=True, indent=4)
        # Test if parser works
        config = Config(conf_file)


def write_trc_files(AD_configs):
    """
    Generate the ISD TRCs and store them into files.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    """
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:' + isd_id + '-V:' + '0'
        trc_file = 'ISD' + isd_id + '/' + file_name + '.crt'
        
        (sig, ver) = generate_signature_keypair()
        (priv, pub) = generate_cryptobox_keypair()
        cert = Certificate.from_values('isp1_address', ver, pub, 'isp1_address',
                                       sig, 0)
        cert64 = \
            base64.standard_b64encode(str(cert).encode('ascii')).decode('ascii')
        core_isps = {'isp1_address' : cert64}

        (sig, ver) = generate_signature_keypair()
        (priv, pub) = generate_cryptobox_keypair()
        cert = Certificate.from_values('registry_key', ver, pub, 'registry_key',
                                       sig, 0)
        cert64 = \
            base64.standard_b64encode(str(cert).encode('ascii')).decode('ascii')
        registry_key = cert64
        
        (sig, ver) = generate_signature_keypair()
        (priv, pub) = generate_cryptobox_keypair()
        cert = Certificate.from_values('path_server', ver, pub, 'path_server',
                                       sig, 0)
        cert64 = \
            base64.standard_b64encode(str(cert).encode('ascii')).decode('ascii')
        path_key = cert64

        cert = 'create_self_signed_SSL_cert()'
        cert64 = \
            base64.standard_b64encode(str(cert).encode('ascii')).decode('ascii')
        root_cas = {'ca1_address' : cert64}
        
        (sig, ver) = generate_signature_keypair()
        (priv, pub) = generate_cryptobox_keypair()
        cert = Certificate.from_values('dns_server', ver, pub, 'dns_server',
                                       sig, 0)
        cert64 = \
            base64.standard_b64encode(str(cert).encode('ascii')).decode('ascii')
        root_dns_key = cert64

        root_dns_addr = '1-11-192.168.1.18'
        trc_server = '1-11-192.168.1.19'
        policies = {}
        signatures = {}
        trc = TRC.from_values(isd_id, 0, core_isps, registry_key, path_key,
            root_cas, root_dns_key, root_dns_addr, trc_server, 3, 3, policies,
            signatures)
        with open(trc_file, 'w') as key_fh:
            key_fh.write(str(trc))
        # Test if parser works
        trc = TRC(trc_file)


def main():
    """
    Main function.
    """
    if not os.path.isfile(ADCONFIGURATIONS_FILE):
        logging.error(ADCONFIGURATIONS_FILE + " file missing.")
        sys.exit()

    try:
        AD_configs = json.loads(open(ADCONFIGURATIONS_FILE).read())
    except (ValueError, KeyError, TypeError):
        logging.error(ADCONFIGURATIONS_FILE + ": JSON format error.")
        sys.exit()

    if "default_subnet" in AD_configs:
        default_subnet = AD_configs["default_subnet"]
        del AD_configs["default_subnet"]
    
    er_ip_addresses = set_er_ip_addresses(AD_configs)

    delete_directories()

    create_directories(AD_configs)

    write_keys_certs(AD_configs)

    write_conf_files(AD_configs)

    write_beginning_setup_run_files(AD_configs)
    
    write_topo_files(AD_configs, er_ip_addresses)

    write_trc_files(AD_configs)


if __name__ == "__main__":
    main()
