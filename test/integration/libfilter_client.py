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
L4_PROTOCOL_NUM = {"scmp": L4Proto.SCMP, "tcp": L4Proto.TCP,
                   "udp": L4Proto.UDP, "ssp": L4Proto.SSP}

# Filter options
EGRESS = 1 << 4
SRC_NEGATED = 1 << 3
DST_NEGATED = 1 << 2
HOP_NEGATED = 1 << 1
FILTER_NEGATED = 1 << 0

# Filter restrictions
ALLOWED_FILTER_MODES = ['accept', 'reject']
ALLOWED_L4_PROTOS = ['scmp', 'tcp', 'udp', 'ssp']
ALLOWED_DIRECTIONS = ['ingress', 'egress']
ALLOWED_FILTER_LEVELS = ['isd', 'as', 'addr', 'port']
MAX_FILTERS_PER_L4 = 255
HELP_COMMAND = 'help'
EXIT_COMMAND = 'exit'


class FilterCommandParser(object):
    """
    Parser for filter commands.
    Helps in converting the commands from a high-level language described in
    the function print_help() below, to a low-level bytestream.
    """

    def print_help(self):
        print('''
The following is the filter command format:
filter_mode direction l4_protocol [src_spec] [dst_spec] [hop_spec])

Where,
    filter_mode = accept/reject
    direction   = ingress/egress
    l4_protocol = scmp/tcp/udp/ssp
    src_spec    = src [not] <node> [<level>]
    dst_spec    = dst [not] <node> [<level>]
    hop_spec    = hop [not] <node> [<level>]

Note:
    If src_spec/dst_spec/hop_spec is absent, then the filter does not
    match src/dst/hop (respectively) of packets while filtering

    <node> should be a SCION node present in the topology (eg. bs1-11-1)

    <level> is the level at which filtering should happen wrt the node:
    Following are the allowed values for it:
    isd/as/addr/port(default)

Examples:
    reject egress tcp
    reject ingress udp src not bs1-11-1 isd
    accept egress ssp dst ps1-11-1 as hop not sb1-11-1
    accept ingress scmp src bs1-11-1 addr dst ps1-12-1 port hop not er1-12er1-11
    ''')

    def parse_cmd(self, command):
        output = {}
        args = command.split()

        # Set mandatory arguments after sanctity checks
        if len(args) < 3:
            logging.error("Insufficient arguments in the filter command")
            return None
        # filter_mode
        output['options'] = 0
        if args[0] not in ALLOWED_FILTER_MODES:
            logging.error("Unknown filter mode specified")
            return None
        if args[0] == 'accept':
            output['options'] |= FILTER_NEGATED
        # direction
        if args[1] not in ALLOWED_DIRECTIONS:
            logging.error("Unknown filter direction specified")
            return None
        if args[1] == 'egress':
            output['options'] |= EGRESS
        # l4_protocol
        if args[2] not in ALLOWED_L4_PROTOS:
            logging.error("Unknown L4 protocol specified")
            return None
        output['l4'] = L4_PROTOCOL_NUM[args[2]]

        # Set src, dst and hop arguments after sanctity checks
        src_pos = args.index("src") if ("src" in args) else len(args)
        dst_pos = args.index("dst") if ("dst" in args) else len(args)
        hop_pos = args.index("hop") if ("hop" in args) else len(args)
        if min(src_pos, dst_pos, hop_pos) > 4:
            logging.error("Unknown argument provided in the filter command")
            return None
        if src_pos != len(args) and src_pos > min(dst_pos, hop_pos):
            logging.error("Src details should preceed those of dst and hop")
            return None
        if dst_pos != len(args) and dst_pos > hop_pos:
            logging.error("Dst details should preceed those of hop")
            return None
        src_args = args[(src_pos + 1):min(dst_pos, hop_pos)]
        dst_args = args[(dst_pos + 1):hop_pos]
        hop_args = args[(hop_pos + 1):]
        # src
        output['srcs'], pattern_negated = self.get_addr_patterns(src_args)
        if output['srcs'] is None:
            logging.error("Invalid src details provided")
            return None
        if pattern_negated:
            output['options'] |= SRC_NEGATED
        # dst
        output['dsts'], pattern_negated = self.get_addr_patterns(dst_args)
        if output['dsts'] is None:
            logging.error("Invalid dst details provided")
            return None
        if pattern_negated:
            output['options'] |= DST_NEGATED
        # hop
        output['hops'], pattern_negated = self.get_addr_patterns(hop_args)
        if output['hops'] is None:
            logging.error("Invalid hop details provided")
            return None
        if pattern_negated:
            output['options'] |= HOP_NEGATED

        return output

    def get_addr_patterns(self, args):
        if args == []:  # No pattern specified
            return ([bytearray(SCION_ADDR_LEN)], False)

        # Obtain the address pattern parameters and perform sanctity checks
        pattern_negated = False
        node = ''
        level = 'port'

        if len(args) == 1:
            node = args[0]
        if len(args) == 2:
            if args[0] == 'not':
                pattern_negated = True
                node = args[1]
            else:
                node = args[0]
                level = args[1]
        if len(args) == 3:
            if args[0] != 'not':
                logging.error("Unknown address pattern field instead of not")
                return (None, None)
            pattern_negated = True
            node = args[1]
            level = args[2]

        if level not in ALLOWED_FILTER_LEVELS:
            logging.error("Unknown filter level specified in address pattern")
            return (None, None)

        # Generate the possible address patterns from the above parameters.
        # Obtain parts of the the address patterns in a hierarchial order as
        # defined by ALLOWED_FILTER_LEVELS.
        filter_pattern = bytearray(SCION_ADDR_LEN)
        offset = 0

        # Obtain ISD and AS of the node
        s_type = node[:2]
        if s_type not in SERVICE_TYPES:
            logging.error("Unknown service type of node in address pattern")
            return (None, None)
        try:
            isd_as_num = node.split(s_type)[1].split('-')
            isd_id = int(isd_as_num[0])
            as_id = int(isd_as_num[1])
        except:
            logging.error("Unknown format for the node name '%s'", node)
            return (None, None)

        # Fill in ISD and AS into the address pattern
        if level == 'isd':
            as_id = 0
        isd_as = ISD_AS.from_values(isd_id, as_id).int()
        struct.pack_into('!I', filter_pattern, offset, isd_as)
        offset += ISD_AS.LEN
        if level in ['isd', 'as']:
            return ([filter_pattern], pattern_negated)

        # Obtain Addr(s) and Port(s) of the node from its topology file
        topo_file = os.path.join(PROJECT_ROOT,
                                 GEN_PATH,
                                 'ISD{}/AS{}'.format(isd_id, as_id),
                                 node,
                                 TOPO_FILE)
        if not os.path.isfile(topo_file):
            logging.error("Node does not exist in the topology")
            return (None, None)
        stream = open(topo_file, "r")
        topology = next(yaml.load_all(stream))
        s_type_full = SERVICE_ALIAS[s_type]
        addrs, ports = self.get_addrs_and_ports(topology[s_type_full][node])

        # Fill in the (Addr, Port) pairs obtained into the address patterns
        filter_patterns = []
        for i in range(len(addrs)):
            filter_pattern_tmp = bytearray(bytes(filter_pattern))
            addr = addrs[i].split('/')[0]
            try:
                addr = ipaddress.ip_address(addr)
                addr_type = IP_ADDRESS_NUM[addr.version]
                addr = addr.packed
            except:
                addr = struct.pack('!H', int(addr))
                addr_type = AddrType.SVC
            struct.pack_into('B', filter_pattern_tmp, offset, addr_type)
            filter_pattern_tmp[(offset + 1):(offset + 1 + len(addr))] = addr
            filter_patterns += [filter_pattern_tmp]
        if level == 'addr':
            return (filter_patterns, pattern_negated)

        offset = offset + 1 + MAX_HOST_ADDR_LEN
        for i in range(len(ports)):
            struct.pack_into('!H', filter_patterns[i], offset, int(ports[i]))
        return (filter_patterns, pattern_negated)

    def get_addrs_and_ports(self, node_topo):
        addrs = [node_topo['Addr']]
        ports = [node_topo['Port']]
        if 'Interface' in node_topo:
            addrs += [node_topo['Interface']['Addr']]
            ports += [node_topo['Interface']['UdpPort']]
        return (addrs, ports)


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
    # Initialize the filter client
    parser = FilterCommandParser()
    header = bytearray()
    payload = bytearray()
    l4_filter_count = {}
    for l4_proto in ALLOWED_L4_PROTOS:
        l4_filter_count[L4_PROTOCOL_NUM[l4_proto]] = 0

    logging.info("Initialized the filter client")
    print("Started the filter client.\n"
          "Enter filter commands one per line. Type 'exit' when you are done.\n"
          "Type 'help' for filter command format info.")

    # Input the filter commands and generate the payload
    while True:
        cmd = input('>>> ')
        if cmd == EXIT_COMMAND:
            logging.info("Finished reading filter commands")
            break
        if cmd == HELP_COMMAND:
            parser.print_help()
            continue

        # Obtain the filter arguments from the command
        args = parser.parse_cmd(cmd)
        if not args:
            logging.error("Neglecting filter: bad format")
            continue

        # Check that filter command limit doesn't exceed for the protocol
        new_filters_count = (l4_filter_count[args['l4']] +
                             (len(args['srcs']) *
                              len(args['dsts']) *
                              len(args['hops'])))
        if new_filters_count > MAX_FILTERS_PER_L4:
            logging.error("Neglecting filter: limit exceeded for protocol %d",
                          args['l4'])
            continue

        # Add the filters to the payload
        for src in args['srcs']:
            for dst in args['dsts']:
                for hop in args['hops']:
                    payload.append(args['l4'])
                    payload += src
                    payload += dst
                    payload += hop
                    payload.append(args['options'])
        l4_filter_count[args['l4']] = new_filters_count

    # Generate the filter header
    for l4 in ALLOWED_L4_PROTOS:
        header.append(l4_filter_count[L4_PROTOCOL_NUM[l4]])

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
