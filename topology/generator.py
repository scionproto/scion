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
from lib.defines import TOPOLOGY_PATH

from lib.topology import Topology
from lib.config import Config
from lib.crypto.certificate import (Certificate, CertificateChain, TRC)
from lib.crypto.asymcrypto import (sign, generate_signature_keypair,
    generate_cryptobox_keypair)
from lib.util import (get_cert_chain_file_path, get_sig_key_file_path,
    get_enc_key_file_path, get_trc_file_path, write_file)
from lib.path_store import PathPolicy
import json
import logging
import shutil
import os
import struct
import socket
import base64
import configparser
import sys


DEFAULT_ADCONFIGURATIONS_FILE = 'ADConfigurations.json'
DEFAULT_PATH_POLICY_FILE = 'PathPolicy.json'

SCRIPTS_DIR = 'topology'
CERT_DIR = 'certificates'
CONF_DIR = 'configurations'
TOPO_DIR = 'topologies'
SIG_KEYS_DIR = 'signature_keys'
ENC_KEYS_DIR = 'encryption_keys'
SETUP_DIR = 'setup'
PATH_POL_DIR = 'path_policies'
SUPERVISOR_DIR = 'supervisor'

CORE_AD = 'CORE'
INTERMEDIATE_AD = 'INTERMEDIATE'
LEAF_AD = 'LEAF'

DEFAULT_BEACON_SERVERS = 1
DEFAULT_CERTIFICATE_SERVERS = 1
DEFAULT_PATH_SERVERS = 1
INITIAL_CERT_VERSION = 0
INITIAL_TRC_VERSION = 0
PORT = '50000'
ISD_AD_ID_DIVISOR = '-'
BS_RANGE = '1'
CS_RANGE = '21'
PS_RANGE = '41'
ER_RANGE = '61'

default_subnet = "127.0.0.0/8"
out_dir = TOPOLOGY_PATH


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
        for link in AD_configs[isd_ad_id].get("links", []):
            er_ip_addresses[(isd_ad_id, link)] = \
                (ip_address_loc, ip_address_pub)
            ip_address_loc = increment_address(ip_address_loc, mask, 2)
            ip_address_pub = increment_address(ip_address_pub, mask, 2)
    return er_ip_addresses


def delete_directories():
    """
    Delete any ISD* directories if present.
    """
    _, dirs, _ = next(os.walk(out_dir))
    for name in dirs:
        if name.startswith('ISD'):
            shutil.rmtree(os.path.join(out_dir, name))


def create_directories(AD_configs):
    """
    Create the ISD* directories and sub-directories, where all files used to run
    the SCION ADs are stored.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    """
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split('-')
        isd_name = 'ISD' + isd_id
        ad_name = 'AD' + ad_id
        cert_path = os.path.join(isd_name, CERT_DIR, ad_name)
        conf_path = os.path.join(isd_name, CONF_DIR)
        topo_path = os.path.join(isd_name, TOPO_DIR)
        sig_keys_path = os.path.join(isd_name, SIG_KEYS_DIR)
        enc_keys_path = os.path.join(isd_name, ENC_KEYS_DIR)
        setup_path = os.path.join(isd_name, SETUP_DIR)
        path_pol_path = os.path.join(isd_name, PATH_POL_DIR)
        supervisor_path = os.path.join(isd_name, SUPERVISOR_DIR)
        paths = [cert_path, conf_path, topo_path, sig_keys_path, enc_keys_path,
                 setup_path, path_pol_path, supervisor_path]
        for path in paths:
            full_path = os.path.join(out_dir, path)
            if not os.path.exists(full_path):
                os.makedirs(full_path)


def write_keys_certs(AD_configs):
    """
    Generate the AD certificates and keys and store them into separate files.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    :returns: the signature and encryption keys.
    :rtype: dict
    """
    sig_priv_keys = {}
    sig_pub_keys = {}
    enc_pub_keys = {}
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        sig_key_file = get_sig_key_file_path(isd_id, ad_id, isd_dir=out_dir)
        enc_key_file = get_enc_key_file_path(isd_id, ad_id, isd_dir=out_dir)
        (sig_pub, sig_priv) = generate_signature_keypair()
        (enc_pub, enc_priv) = generate_cryptobox_keypair()
        sig_priv_keys[isd_ad_id] = sig_priv
        sig_pub_keys[isd_ad_id] = sig_pub
        enc_pub_keys[isd_ad_id] = enc_pub
        sig_priv = base64.b64encode(sig_priv).decode('utf-8')
        enc_priv = base64.b64encode(enc_priv).decode('utf-8')
        write_file(sig_key_file, sig_priv)
        write_file(enc_key_file, enc_priv)
    certs = {}
    for isd_ad_id in AD_configs:
        if AD_configs[isd_ad_id]['level'] != CORE_AD:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            iss_isd_ad_id = AD_configs[isd_ad_id]['cert_issuer']
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
                                             isd_dir=out_dir)
        write_file(cert_file, str(chain))
        # Test if parser works
        cert = CertificateChain(cert_file)
    return {'sig_priv_keys': sig_priv_keys,
            'sig_pub_keys': sig_pub_keys,
            'enc_pub_keys': enc_pub_keys}


def _path_dict(isd_id, ad_id):
    isd_name = 'ISD' + isd_id
    file_name = 'ISD:' + isd_id + '-AD:' + ad_id
    setup_file = os.path.join(out_dir, isd_name,
                              SETUP_DIR, file_name + '.sh')
    supervisor_file = os.path.join(out_dir, isd_name,
                                   SUPERVISOR_DIR, file_name + '.conf')
    topo_file = os.path.join(isd_name, TOPO_DIR, file_name + '.json')
    topo_file_rel = os.path.join("..", SCRIPTS_DIR, topo_file)
    conf_file_rel = os.path.join("..", SCRIPTS_DIR, isd_name, CONF_DIR,
                                 file_name + '.conf')
    trc_file = get_trc_file_path(isd_id, ad_id, isd_id, INITIAL_TRC_VERSION,
                                 isd_dir=out_dir)
    trc_file_rel = os.path.join('..', SCRIPTS_DIR,
                                os.path.relpath(trc_file, out_dir))
    path_pol_file_rel = os.path.join("..", SCRIPTS_DIR, isd_name,
                                     PATH_POL_DIR, file_name + '.json')
    return locals()


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
        p = _path_dict(isd_id, ad_id)
        topo_file = p['topo_file']
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

        # Write Beacon Servers
        ip_address = '.'.join([first_byte, isd_id, ad_id, BS_RANGE])
        for b_server in range(1, number_bs + 1):
            topo_dict['BeaconServers'][b_server] = {'AddrType': 'IPv4',
                                                    'Addr': ip_address}
            ip_address = increment_address(ip_address, mask)
        # Write Certificate Servers
        ip_address = '.'.join([first_byte, isd_id, ad_id, CS_RANGE])
        for c_server in range(1, number_cs + 1):
            topo_dict['CertificateServers'][c_server] = {'AddrType': 'IPv4',
                                                         'Addr': ip_address}
            ip_address = increment_address(ip_address, mask)
        # Write Path Servers
        if (AD_configs[isd_ad_id]['level'] != INTERMEDIATE_AD or
            "path_servers" in AD_configs[isd_ad_id]):
            ip_address = '.'.join([first_byte, isd_id, ad_id, PS_RANGE])
            for p_server in range(1, number_ps + 1):
                topo_dict['PathServers'][p_server] = {'AddrType': 'IPv4',
                                                      'Addr': ip_address}
                ip_address = increment_address(ip_address, mask)
        # Write Edge Routers
        edge_router = 1
        for nbr_isd_ad_id in AD_configs[isd_ad_id].get("links", []):
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
            edge_router += 1

        topo_file_abs = os.path.join(out_dir, topo_file)
        with open(topo_file_abs, 'w') as topo_fh:
            json.dump(topo_dict, topo_fh, sort_keys=True, indent=4)
        # Test if parser works
        topology = Topology(topo_file_abs)

        write_supervisor_config(topo_dict)
        write_setup_file(topo_dict, mask)


def _get_typed_elements(topo_dict):
    """
    Generator which iterates over all the elements in the topology
    supplemented with the corresponding type label.
    """
    element_types = ['BeaconServers', 'CertificateServers',
                     'PathServers', 'EdgeRouters']
    for element_type in element_types:
        for element_num, element_dict in topo_dict[element_type].items():
            yield (element_num, element_dict, element_type)


def write_setup_file(topo_dict, mask=None):
    if mask is None:
        mask = default_subnet.split('/')[1]

    p = _path_dict(str(topo_dict['ISDID']), str(topo_dict['ADID']))
    preamble = '#!/bin/bash\n\n'

    with open(p['setup_file'], 'a') as setup_fh:
        setup_fh.write(preamble)
        for (_, element_dict, element_type) in _get_typed_elements(topo_dict):
            ip_address = element_dict['Addr']
            ip_add = 'ip addr add {}/{} dev lo\n'.format(ip_address, mask)
            setup_fh.write(ip_add)


def write_supervisor_config(topo_dict):
    supervisor_common = {
        'autostart': 'false',
        'autorestart': 'false',
        'redirect_stderr': 'true',
        'environment': 'PYTHONPATH=..',
        'stdout_logfile_maxbytes': '0',
        'startretries': '1',
    }

    program_group = []
    supervisor_config = configparser.ConfigParser()

    isd_id, ad_id = str(topo_dict['ISDID']), str(topo_dict['ADID'])
    p = _path_dict(isd_id, ad_id)

    for (num, element_dict, element_type) in _get_typed_elements(topo_dict):
        ip_address = element_dict['Addr']
        element_location = 'core' if topo_dict['Core'] else 'local'
        if element_type == 'BeaconServers':
            element_name = 'bs{}-{}-{}'.format(isd_id, ad_id, num)
            cmd_args = ['beacon_server.py',
                        element_location,
                        ip_address,
                        p['topo_file_rel'],
                        p['conf_file_rel'],
                        p['path_pol_file_rel']]

        elif element_type == 'CertificateServers':
            element_name = 'cs{}-{}-{}'.format(isd_id, ad_id, num)
            cmd_args = ['cert_server.py',
                        ip_address,
                        p['topo_file_rel'],
                        p['conf_file_rel'],
                        p['trc_file_rel']]
        elif element_type == 'PathServers':
            element_name = 'ps{}-{}-{}'.format(isd_id, ad_id, num)
            cmd_args = ['path_server.py',
                        element_location,
                        ip_address,
                        p['topo_file_rel'],
                        p['conf_file_rel']]

        elif element_type == 'EdgeRouters':
            interface_dict = element_dict['Interface']
            nbr_isd_id = interface_dict['NeighborISD']
            nbr_ad_id = interface_dict['NeighborAD']
            element_name = 'er{}-{}er{}-{}'.format(isd_id, ad_id,
                                                   nbr_isd_id, nbr_ad_id)
            cmd_args = ['router.py',
                        ip_address,
                        p['topo_file_rel'],
                        p['conf_file_rel']]
        else:
            assert False, 'Invalid element type'

        command_line = ('/usr/bin/python3 '
                        + ' '.join(['"{}"'.format(arg) for arg in cmd_args]))
        log_file = '../logs/{}.log'.format(element_name)
        server_config = supervisor_common.copy()
        server_config.update({'command': command_line,
                              'stdout_logfile': log_file})

        supervisor_config['program:' + element_name] = server_config
        program_group.append(element_name)

    group_header = "group:ad{}-{}".format(isd_id, ad_id)
    supervisor_config[group_header] = {'programs': ','.join(program_group)}

    # Write config
    with open(p['supervisor_file'], 'w') as conf_fh:
        supervisor_config.write(conf_fh)


def write_conf_files(AD_configs):
    """
    Generate the AD configurations and store them into files.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    """
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:{}-AD:{}.conf'.format(isd_id, ad_id)
        conf_file = os.path.join(out_dir, 'ISD' + isd_id,
                                 CONF_DIR, file_name)
        conf_dict = {'MasterOFGKey': 1234567890,
                     'MasterADKey': 1919191919,
                     'PCBQueueSize': 10,
                     'PSQueueSize': 10,
                     'NumRegisteredPaths': 10,
                     'NumShortestUPs': 3,
                     'RegisterTime': 5,
                     'PropagateTime': 5,
                     'ResetTime': 600,
                     'CertChainVersion': 0}
        if (AD_configs[isd_ad_id]['level'] != INTERMEDIATE_AD or
            "path_servers" in AD_configs[isd_ad_id]):
            conf_dict['RegisterPath'] = 1
        else:
            conf_dict['RegisterPath'] = 0
        with open(conf_file, 'w') as conf_fh:
            json.dump(conf_dict, conf_fh, sort_keys=True, indent=4)
        # Test if parser works
        config = Config(conf_file)


def write_path_pol_files(AD_configs, path_policy_file):
    """
    Generate the AD path policies and store them into files.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    """
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:{}-AD:{}.json'.format(isd_id, ad_id)
        new_path_pol_file = os.path.join(out_dir, 'ISD' + isd_id,
                                         PATH_POL_DIR, file_name)
        shutil.copyfile(path_policy_file, new_path_pol_file)
        # Test if parser works
        path_policy = PathPolicy(new_path_pol_file)


def write_trc_files(AD_configs, keys):
    """
    Generate the ISD TRCs and store them into files.

    :param AD_configs: the configurations of all SCION ADs.
    :type AD_configs: dict
    :param keys: the signature and encryption keys.
    :type: dict
    """
    for isd_ad_id in AD_configs:
        if AD_configs[isd_ad_id]['level'] == CORE_AD:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            file_name = 'ISD:{}-V:{}.crt'.format(isd_id,
                                                 str(INITIAL_TRC_VERSION))
            trc_file = os.path.join(out_dir, 'ISD' + isd_id, file_name)
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
                write_file(trc_file, str(trc))
                # Test if parser works
                trc = TRC(trc_file)
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
                    core_ads, {}, registry_server_addr, registry_server_cert,
                    root_dns_server_addr, root_dns_server_cert, trc_server_addr,
                    signatures)
                write_file(trc_file, str(trc))
                # Test if parser works
                trc = TRC(trc_file)
    for isd_ad_id in AD_configs:
        if AD_configs[isd_ad_id]['level'] == CORE_AD:
            (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
            file_name = 'ISD:{}-V:0.crt'.format(isd_id)
            trc_file = os.path.join(out_dir, 'ISD' + isd_id, file_name)
            subject = 'ISD:' + isd_id + '-AD:' + ad_id
            if os.path.exists(trc_file):
                trc = TRC(trc_file)
                data_to_sign = trc.__str__(with_signatures=False)
                data_to_sign = data_to_sign.encode('utf-8')
                sig = sign(data_to_sign, keys['sig_priv_keys'][isd_ad_id])
                trc.signatures[subject] = sig
                write_file(trc_file, str(trc))
                # Test if parser works
                trc = TRC(trc_file)
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:{}-V:0.crt'.format(isd_id)
        trc_file = os.path.join(out_dir, 'ISD' + isd_id, file_name)
        if os.path.exists(trc_file):
            dst_path = get_trc_file_path(isd_id, ad_id, isd_id, 0,
                                         isd_dir=out_dir)
            shutil.copyfile(trc_file, dst_path)
    for isd_ad_id in AD_configs:
        (isd_id, ad_id) = isd_ad_id.split(ISD_AD_ID_DIVISOR)
        file_name = 'ISD:{}-V:0.crt'.format(isd_id)
        trc_file = os.path.join(out_dir, 'ISD' + isd_id, file_name)
        if os.path.exists(trc_file):
            os.remove(trc_file)


def main():
    """
    Main function.
    """
    if len(sys.argv) == 1:
        adconfigurations_file = DEFAULT_ADCONFIGURATIONS_FILE
        path_policy_file = DEFAULT_PATH_POLICY_FILE
    elif len(sys.argv) == 4:
        global out_dir
        adconfigurations_file = sys.argv[1]
        path_policy_file = sys.argv[2]
        out_dir = os.path.abspath(sys.argv[3])
    else:
        logging.error('Invalid number of arguments. '
                      'RUN: %s ad_confs_file path_policy_file out_dir',
                      sys.argv[0])
        sys.exit()

    if not os.path.isfile(adconfigurations_file):
        logging.error(adconfigurations_file + " file missing.")
        sys.exit()

    if not os.path.isfile(path_policy_file):
        logging.error(path_policy_file + " file missing.")
        sys.exit()

    if not os.path.isdir(out_dir):
        logging.error(out_dir + " output directory missing")
        sys.exit()

    try:
        AD_configs = json.loads(open(adconfigurations_file).read())
    except (ValueError, KeyError, TypeError):
        logging.error(adconfigurations_file + ": JSON format error.")
        sys.exit()

    if "default_subnet" in AD_configs:
        global default_subnet
        default_subnet = AD_configs["default_subnet"]
        del AD_configs["default_subnet"]

    er_ip_addresses = set_er_ip_addresses(AD_configs)

    delete_directories()

    create_directories(AD_configs)

    keys = write_keys_certs(AD_configs)

    write_conf_files(AD_configs)

    write_path_pol_files(AD_configs, path_policy_file)

    write_topo_files(AD_configs, er_ip_addresses)

    write_trc_files(AD_configs, keys)


if __name__ == "__main__":
    main()
