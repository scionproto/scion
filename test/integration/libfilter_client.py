#!/usr/bin/python3
# Copyright 2016 ETH Zurich
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
:mod:`libfilter_client` --- SCION libfilter client
==================================================
"""
# Stdlib
import argparse
import ipaddress
import logging
import os
import socket
import struct
import sys
import yaml

# SCION
from lib.defines import (
    GEN_PATH,
    MAX_HOST_ADDR_LEN,
    PROJECT_ROOT,
    SCION_FILTER_CMD_PORT,
    SERVICE_TYPES,
    TOPO_FILE
)
from lib.log import init_logging, log_exception
from lib.main import main_wrapper
from lib.packet.scion_addr import ISD_AS
from lib.types import AddrType, L4Proto
from lib.util import handle_signals

# Some constants
SCION_ADDR_LEN = 4 + (MAX_HOST_ADDR_LEN + 1 + 2)  # isd_as + Addr(+type) + Port
SERVICE_ALIAS = {"er": "EdgeRouters", "bs": "BeaconServers",
                 "cs": "CertificateServers", "ps": "PathServers",
                 "sb": "SibraServers"}
IP_ADDRESS_NUM = {4: AddrType.IPV4, 6: AddrType.IPV6}
L4_PROTOCOL_NUM = {"SCMP": L4Proto.SCMP, "TCP": L4Proto.TCP,
                   "UDP": L4Proto.UDP, "SSP": L4Proto.SSP}

# Filter options
EGRESS = 1 << 4
SRC_NEGATED = 1 << 3
DST_NEGATED = 1 << 2
HOP_NEGATED = 1 << 1
FILTER_NEGATED = 1 << 0

# Filter restrictions
ALLOWED_FILTER_MODES = ['ALLOW', 'BLOCK']
ALLOWED_L4_PROTOS = ['SCMP', 'TCP', 'UDP', 'SSP']  # Order is important
ALLOWED_DIRECTIONS = ['INGRESS', 'EGRESS']
ALLOWED_FILTER_LEVELS = ['ISD', 'AS', 'ADDR', 'PORT']  # Order is important
MAX_FILTERS_PER_L4 = 255
EXIT_COMMAND = 'exit'


def init_filter_parser():
    parser = argparse.ArgumentParser(description='''
        Input filter commands following the format specified by the parser.
        Type 'exit' (without quotes) if there are no more commands to be given.
        ''')
    parser.add_argument(dest='filter_mode', action='store',
                        choices=ALLOWED_FILTER_MODES,
                        help='Filter allows/blocks matching packets')
    parser.add_argument(dest='l4_proto', action='store',
                        choices=ALLOWED_L4_PROTOS,
                        help='L4 protocol to be filtered')
    parser.add_argument(dest='direction', action='store',
                        choices=ALLOWED_DIRECTIONS,
                        help='Filtering at the hop\'s ingress/egress interface')
    parser.add_argument('-S', dest='src', action='store', default='',
                        help='Source of the packets to be filtered',
                        metavar='(!)NODE:LEVEL')
    parser.add_argument('-D', dest='dst', action='store', default='',
                        help='Destination of the packets to be filtered',
                        metavar='(!)NODE:LEVEL')
    parser.add_argument('-H', dest='hop', action='store', default='',
                        help='Hop of the packets to be filtered',
                        metavar='(!)NODE:LEVEL')
    return parser


def get_addrs_and_ports(node_topo):
    addrs = [node_topo['Addr']]
    ports = [node_topo['Port']]
    if 'Interface' in node_topo:
        addrs += node_topo['Interface']['Addr']
        ports += node_topo['Interface']['UdpPort']
    return (addrs, ports)


def get_filter_addrs(pattern):
    filter_addr = bytearray(SCION_ADDR_LEN)
    offset = 0

    if (pattern == ''):  # No pattern specified
        return ([filter_addr], False)

    # Find if the pattern has been negated
    pattern_negated = False
    if pattern[0] == '!':
        pattern_negated = True
        pattern = pattern[1:]

    # Obtain the name of the node and the filter level (seperated by a ':')
    if pattern.count(':') != 1:
        logging.error("Badly formatted filter address pattern: "
                      "incorrect number of ':' seperators given")
        return ([], '')
    node, level = pattern.split(':')
    if level not in ALLOWED_FILTER_LEVELS:
        logging.error("Unknown filter level specified in the address pattern")
        return ([], '')

    # Obtain ISD and AS of the node
    s_type = node[:2]
    if s_type not in SERVICE_TYPES:
        logging.error("Unknown service type of node in the pattern")
        return ([], '')
    try:
        isd_as_num = node.split(s_type)[1].split('-')
        isd_id = int(isd_as_num[0])
        as_id = int(isd_as_num[1])
    except:
        logging.error("Unknown format for the node name [%s]", node)
        return ([], '')

    # Fill in ISD and AS into the filter address
    if level == 'ISD':
        as_id = 0
    isd_as = ISD_AS.from_values(isd_id, as_id).int()
    struct.pack_into('!I', filter_addr, offset, isd_as)
    offset += ISD_AS.LEN
    if level in ['ISD', 'AS']:
        return (filter_addr, pattern_negated)

    # Open the topology file corresponding to the node
    topo_file = os.path.join(PROJECT_ROOT,
                             GEN_PATH,
                             'ISD{}/AS{}'.format(isd_id, as_id),
                             node,
                             TOPO_FILE)
    if not os.path.isfile(topo_file):
        logging.error("Node does not exist in the topology")
        return ([], '')
    stream = open(topo_file, "r")
    topology = next(yaml.load_all(stream))
    s_type_full = SERVICE_ALIAS[s_type]

    # Obtain the address(es) and port(s) corresponding to the node
    addrs, ports = get_addrs_and_ports(topology[s_type_full][node])
    filter_addrs = []

    for i in range(len(addrs)):
        filter_addr_tmp = filter_addr
        addr = addrs[i].split('/')[0]
        try:
            addr = ipaddress.ip_address(addr)
            addr_type = ipaddress.ip_address(addr).version
            addr_type = IP_ADDRESS_NUM[addr_type]
            addr = addr.packed
        except:
            addr_type = AddrType.SVC
            addr = struct.pack('!H', int(addr))
        struct.pack_into('B', filter_addr_tmp, offset, addr_type)
        filter_addr_tmp[(offset + 1):(offset + 1 + len(addr))] = addr
        filter_addrs += [filter_addr_tmp]

    if level == 'ADDR':
        return (filter_addrs, pattern_negated)

    offset = offset + 1 + MAX_HOST_ADDR_LEN
    for i in range(len(ports)):
        struct.pack_into('!H', filter_addrs[i], offset, int(ports[i]))
    return (filter_addrs, pattern_negated)


def send_filters(header, payload):
    # Create a connection with libfilter
    try:
        port = SCION_FILTER_CMD_PORT
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.connect(('', port))
        logging.info("Client connected to libfilter")
    except:
        logging.error("Connection to libfilter failed... "
                      "closing down the client")
        sock.close()
        return

    # Send the filter header and payload
    try:
        sock.send(header)
        sock.send(payload)
        logging.info("Sent the filters successfully... "
                     "closing down the client")
    except:
        logging.error("Failed to send the filters... "
                      "closing down the client")
    sock.close()


def main():
    # Initialize the filter command parser and filter counts for the l4 protos
    parser = init_filter_parser()
    filter_count = {}
    for l4_proto in ALLOWED_L4_PROTOS:
        filter_count[l4_proto] = 0
    logging.info("Initialized the filter client")

    # Initialize the filter command batch's header and payload
    header = bytearray()
    payload = bytearray()

    # Input the filter commands and generate the payload
    while True:
        cmd = input()
        if cmd == EXIT_COMMAND:
            logging.info("Finished reading filter commands")
            break
        try:
            args = cmd.split()
            args = parser.parse_args(args)
        except:
            logging.error("Neglecting filter: "
                          "Badly formatted filter command [%s]", cmd)
            continue

        # Obtain src, dst and hop address patterns
        srcs, srcs_negated = get_filter_addrs(args.src)
        if srcs == []:
            logging.error("Neglecting filter: "
                          "Badly formatted src specification: [%s]", args.src)
            continue
        dsts, dsts_negated = get_filter_addrs(args.dst)
        if dsts == []:
            logging.error("Neglecting filter: "
                          "Badly formatted dst specification: [%s]", args.dst)
            continue
        hops, hops_negated = get_filter_addrs(args.hop)
        if hops == []:
            logging.error("Neglecting filter: "
                          "Badly formatted hop specification: [%s]", args.hop)
            continue

        # Check that the filter limit has not been reached for the L4 proto
        new_filters_count = (filter_count[args.l4_proto] +
                             len(srcs) * len(dsts) * len(hops))
        if (new_filters_count > MAX_FILTERS_PER_L4):
            logging.error("Neglecting filter(s): "
                          "Exceeding limit of %d filters for %s protocol",
                          MAX_FILTERS_PER_L4, args.l4_proto)

        # Obtain the filter options.
        # default = (BLOCK, INGRESS, src/dst/hop addrs not negated)
        options = 0
        if args.filter_mode == 'ALLOW':
            options |= FILTER_NEGATED
        if args.direction == 'EGRESS':
            options |= EGRESS
        if srcs_negated:
            options |= SRC_NEGATED
        if dsts_negated:
            options |= DST_NEGATED
        if hops_negated:
            options |= HOP_NEGATED

        # Add the filters to the payload
        l4 = L4_PROTOCOL_NUM[args.l4_proto]
        for src in srcs:
            for dst in dsts:
                for hop in hops:
                    payload.append(l4)
                    payload += src
                    payload += dst
                    payload += hop
                    payload.append(options)
        filter_count[args.l4_proto] = new_filters_count

    # Generate the filter header
    for l4 in ALLOWED_L4_PROTOS:
        header.append(filter_count[l4])

    send_filters(header, payload)


if __name__ == "__main__":
    init_logging("logs/filter_client", console_level=logging.DEBUG)
    handle_signals()
    try:
        main_wrapper(main)
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
