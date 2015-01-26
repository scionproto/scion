import os
import shutil
import socket
import struct
import subprocess
import sys

from lib.crypto.certificates import *
from lib.crypto.trcs import TRC


ADTOISD_FILE = 'ADToISD'
ADRELATIONSHIPS_FILE = 'ADRelationships'

SCRIPTS_DIR = '/topology/'
CERT_DIR = '/certificates/'
CONF_DIR = '/configurations/'
TOPO_DIR = '/topologies/'
SIG_KEYS_DIR = '/signature_keys/'
ENC_KEYS_DIR = '/encryption_keys/'
SETUP_DIR = '/setup/'
RUN_DIR = '/run/'

CORE_AD = '0'
INTERMDEDIATE_AD = '1'
LEAF_AD = '2'

PEER_PEER = '0'
CHILD_PARENT = '-1'
ROUTING_ROUTING = '1'


def is_good_ipv4(string):
    pieces = string.split('.')
    if len(pieces) != 4:
        return False
    try:
        return all(0<=int(p)<256 for p in pieces)
    except ValueError:
        return False


def increment_address(ip_address):
    ip2int = lambda ipstr: struct.unpack('!I', socket.inet_aton(ipstr))[0]
    int2ip = lambda n: socket.inet_ntoa(struct.pack('!I', n))
    ip_address_int = ip2int(ip_address)
    ip_address_int += 1
    ip_address = int2ip(ip_address_int)
    return ip_address


def delete_directories():
    for root, dirs, files in os.walk('.'):
        for name in dirs:
            if name.startswith(('ISD')):
                shutil.rmtree(name)


def create_directories(ADToISD_tuples):
    for ad_id, isd_id, relationship in ADToISD_tuples:
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


def write_keys_certs(ADToISD_tuples):
    for ad_id, isd_id, relationship in ADToISD_tuples:
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


def write_beginning_setup_run_files(ADToISD_tuples):
    for ad_id, isd_id, relationship in ADToISD_tuples:
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id
        setup_file = 'ISD' + isd_id + SETUP_DIR + file_name + '.sh'
        run_file = 'ISD' + isd_id + RUN_DIR + file_name + '.sh'
        with open(setup_file, 'w') as setup_fh:
            setup_fh.write('#!/bin/bash\n\n')
        with open(run_file, 'w') as run_fh:
            run_fh.write('#!/bin/bash\n\n')


def write_beginning_topo_files(ADToISD_tuples, ip_address):
    for ad_id, isd_id, relationship in ADToISD_tuples:
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id + '-V:' + '0'
        conf_file = 'ISD' + isd_id + CONF_DIR + file_name + '.conf'
        topo_file = 'ISD' + isd_id + TOPO_DIR + file_name + '.xml'
        rot_file = 'ISD' + isd_id + '/' + 'ISD:' + isd_id + '-V:0.xml'
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id
        setup_file = 'ISD' + isd_id + SETUP_DIR + file_name + '.sh'
        run_file = 'ISD' + isd_id + RUN_DIR + file_name + '.sh'
        is_core = False
        if relationship == CORE_AD:
            is_core = True
        with open(topo_file, 'w') as topo_fh, \
            open(setup_file, 'a') as setup_fh, open(run_file, 'a') as run_fh:
            topo_fh.write('\n'.join([
                '<?xml version=\"1.0\" ?>',
                '<Topology>',
                '\t<Core>' + ('1' if is_core else '0') + '</Core>',
                '\t<ISDID>' + isd_id + '</ISDID>',
                '\t<ADID>' + ad_id + '</ADID>',
                '\t<Servers>',
                '\t\t<BeaconServer>',
                '\t\t\t<AddrType>IPv4</AddrType>',
                '\t\t\t<Addr>' + ip_address + '</Addr>',
                '\t\t</BeaconServer>\n']))
            setup_fh.write('ip addr add ' + ip_address + '/8 dev lo\n')
            run_fh.write(''.join([
                'screen -d -m -S bs' + ad_id + ' sh -c \"',
                'PYTHONPATH=../ python3 beacon_server.py ' + ('core ' if is_core
                else 'local ') + ip_address + ' ',
                '..' + SCRIPTS_DIR + topo_file + ' ',
                '..' + SCRIPTS_DIR + conf_file + '\"\n']))
            ip_address = increment_address(ip_address)
            topo_fh.write('\n'.join([
                '\t\t<CertificateServer>',
                '\t\t\t<AddrType>IPv4</AddrType>',
                '\t\t\t<Addr>' + ip_address + '</Addr>',
                '\t\t</CertificateServer>\n']))
            setup_fh.write('ip addr add ' + ip_address + '/8 dev lo\n')
            run_fh.write(''.join([
                'screen -d -m -S cs' + ad_id + ' sh -c \"',
                "PYTHONPATH=../ python3 cert_server.py " + ip_address + ' ',
                '..' + SCRIPTS_DIR + topo_file + ' ',
                '..' + SCRIPTS_DIR + conf_file + ' ',
                '..' + SCRIPTS_DIR + rot_file + '\"\n']))
            ip_address = increment_address(ip_address)
            if relationship == CORE_AD or relationship == LEAF_AD:
                topo_fh.write('\n'.join([
                    '\t\t<PathServer>',
                    '\t\t\t<AddrType>IPv4</AddrType>',
                    '\t\t\t<Addr>' + ip_address + '</Addr>',
                    '\t\t</PathServer>\n']))
                setup_fh.write('ip addr add ' + ip_address + '/8 dev lo\n')
                run_fh.write(''.join([
                    'screen -d -m -S ps' + ad_id + ' sh -c \"',
                    'PYTHONPATH=../ python3 path_server.py ' + ('core '
                    if is_core else 'local ') + ip_address + ' ',
                    '..' + SCRIPTS_DIR + topo_file + ' ',
                    '..' + SCRIPTS_DIR + conf_file + '\"\n']))
                ip_address = increment_address(ip_address)
            topo_fh.write('\t</Servers>\n\t<BorderRouters>\n')
    return ip_address


def write_routers(ADRelationships_tuples, ads, port, if_id, ip_address):
    for ad_id, nbr_ad_id, relationship in ADRelationships_tuples:
        if relationship == PEER_PEER:
            nbr_type1 = 'PEER'
            nbr_type2 = 'PEER'
        elif relationship == CHILD_PARENT:
            nbr_type1 = 'CHILD'
            nbr_type2 = 'PARENT'
        elif relationship == ROUTING_ROUTING:
            nbr_type1 = 'ROUTING'
            nbr_type2 = 'ROUTING'
        else:
            nbr_type1 = 'UNKNOWN'
            nbr_type2 = 'UNKNOWN'
        (if_id, ip_address) = write_router(ads[ad_id][1], ads[nbr_ad_id][1],
            ad_id, nbr_ad_id, nbr_type1, ads[ad_id][0], ads[nbr_ad_id][0], port,
            port, if_id, ip_address)
        (if_id, ip_address) = write_router(ads[nbr_ad_id][1], ads[ad_id][1],
            nbr_ad_id, ad_id, nbr_type2, ads[nbr_ad_id][0], ads[ad_id][0], port,
            port, if_id, ip_address)
        port += 1
    return ip_address


def write_router(isd_id, nbr_isd_id, ad_id, nbr_ad_id, nbr_type, ext_addr,
    ext_to_addr, ext_udp_port, ext_to_udp_port, if_id, ip_address):
    file_name = 'ISD:' + isd_id + '-AD:' + ad_id + '-V:' + '0'
    conf_file = 'ISD' + isd_id + CONF_DIR + file_name + '.conf'
    topo_file = 'ISD' + isd_id + TOPO_DIR + file_name + '.xml'
    file_name = 'ISD:' + isd_id + '-AD:' + ad_id
    setup_file = 'ISD' + isd_id + SETUP_DIR + file_name + '.sh'
    run_file = 'ISD' + isd_id + RUN_DIR + file_name + '.sh'
    with open(topo_file, 'a') as topo_fh:
        topo_fh.write('\n'.join([
            '\t\t<Router>',
            '\t\t\t<AddrType>IPv4</AddrType>',
            '\t\t\t<Addr>' + ip_address + '</Addr>',
            '\t\t\t<Interface>',
            '\t\t\t\t<IFID>' + str(if_id) + '</IFID>',
            '\t\t\t\t<NeighborISD>' + nbr_isd_id + '</NeighborISD>',
            '\t\t\t\t<NeighborAD>' + nbr_ad_id + '</NeighborAD>',
            '\t\t\t\t<NeighborType>' + nbr_type + '</NeighborType>',
            '\t\t\t\t<AddrType>IPv4</AddrType>',
            '\t\t\t\t<Addr>' + ext_addr + '</Addr>',
            '\t\t\t\t<ToAddr>' + ext_to_addr + '</ToAddr>',
            '\t\t\t\t<UdpPort>' + str(ext_udp_port) + '</UdpPort>',
            '\t\t\t\t<ToUdpPort>' + str(ext_to_udp_port) + '</ToUdpPort>',
            '\t\t\t</Interface>',
            '\t\t</Router>\n']))
    with open(setup_file, 'a') as setup_fh:
        setup_fh.write('ip addr add ' + ip_address + '/8 dev lo\n')
    with open(run_file, 'a') as run_fh:
        run_fh.write(''.join([
            'screen -d -m -S r' + ad_id + 'r' + nbr_ad_id + ' sh -c \"',
            'PYTHONPATH=../ python3 router.py ' + ip_address + ' ',
            '..' + SCRIPTS_DIR + topo_file + ' ',
            '..' + SCRIPTS_DIR + conf_file + '\"\n']))
    if_id += 1
    ip_address = increment_address(ip_address)
    return (if_id, ip_address)


def write_end_topo_files(ADToISD_tuples):
    for ad_id, isd_id, relationship in ADToISD_tuples:
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id + '-V:' + '0'
        topo_file = 'ISD' + isd_id + TOPO_DIR + file_name + '.xml'
        with open(topo_file, 'a') as topo_fh:
            topo_fh.write('\t</BorderRouters>\n</Topology>\n')


def write_conf_files(ADToISD_tuples):
    for ad_id, isd_id, relationship in ADToISD_tuples:
        conf_path = 'ISD' + isd_id + CONF_DIR
        file_name = 'ISD:' + isd_id + '-AD:' + ad_id + '-V:' + '0'
        conf_file = conf_path + file_name + '.conf'
        with open(conf_file, 'w') as conf_fh:
            conf_content = '\n'.join([
                'MasterOFGKey 1234567890',
                'MasterADKey 1919191919',
                'PCBQueueSize 10',
                'PSQueueSize 10',
                'NumRegisteredPaths 10',
                'NumShortestUPs 3',
                'RegisterTime 5',
                'PropagateTime 5',
                'ResetTime 600',
                'RegisterPath '])
            if relationship == CORE_AD or relationship == LEAF_AD:
                conf_content += '1'
            else:
                conf_content += '0'
            conf_fh.write(conf_content)


def write_trc_files(CoreADs_tuples):
    for ad_id, isd_id in CoreADs_tuples:
        trc_path = 'ISD' + isd_id + '/'
        file_name = 'ISD:' + isd_id + '-V:' + '0'
        trc_file = trc_path + file_name + '.crt'
        # sig_key_file = sig_keys_path + file_name + '.key'
        # enc_key_file = enc_keys_path + file_name + '.key'
        # (sig_priv, sig_pub, enc_priv, enc_pub) = generate_keys()
        # TODO: replace static values with real ones
        core_isps = {'isp1.com' : 'xyzxyzxyz', 'isp2.com' : 'xyzxyzxyz',
            'isp3.com' : 'xyzxyzxyz'}
        registry_key = 'xyzxyzxyz'
        path_key = 'xyzxyzxyz'
        root_cas = {'ca1.com' : 'xyzxyzxyz', 'ca2.com' : 'xyzxyzxyz',
            'ca3.com' : 'xyzxyzxyz'}
        root_dns_key = 'xyzxyzxyz'
        root_dns_addr = 'dns_address'
        trc_server = 'trc_address'
        policies = {}
        signatures = {}
        trc = TRC.from_values(isd_id, 0, core_isps, registry_key, path_key,
            root_cas, root_dns_key, root_dns_addr, trc_server, 3, 3, policies,
            signatures)
        with open(trc_file, 'w') as key_fh:
            key_fh.write(str(trc))


def main():
    """
    Main function.
    """
    if not os.path.isfile(ADTOISD_FILE):
        print("ADToISD file missing.")
        sys.exit()

    if not os.path.isfile(ADRELATIONSHIPS_FILE):
        print("ADRelationships file missing.")
        sys.exit()

    if len(sys.argv) != 1 and is_good_ipv4(sys.argv[1]):
        ip_address = sys.argv[1]
    else:
        ip_address = "127.0.0.1"
    
    if_id = 1
    port = 50000

    ads = {}
    ADToISD_tuples = []
    ADRelationships_tuples = []
    CoreADs_tuples = []

    with open(ADTOISD_FILE, 'r') as file_handler:
        for line in file_handler:
            (ad_id, isd_id, relationship) = line.split()
            ADToISD_tuples.append([ad_id, isd_id, relationship])
            if relationship == '0':
                CoreADs_tuples.append([ad_id, isd_id])

    with open(ADRELATIONSHIPS_FILE, 'r') as file_handler:
        for line in file_handler:
            ADRelationships_tuples.append([i for i in line.split()])

    for ad_id, isd_id, relationship in ADToISD_tuples:
        ads[ad_id] = (ip_address, isd_id)
        ip_address = increment_address(ip_address)

    delete_directories()

    create_directories(ADToISD_tuples)

    write_keys_certs(ADToISD_tuples)

    write_conf_files(ADToISD_tuples)

    write_beginning_setup_run_files(ADToISD_tuples)

    ip_address = write_beginning_topo_files(ADToISD_tuples, ip_address)

    ip_address = write_routers(ADRelationships_tuples, ads, port, if_id,
        ip_address)

    write_end_topo_files(ADToISD_tuples)

    write_trc_files(CoreADs_tuples)


if __name__ == "__main__":
    main()
