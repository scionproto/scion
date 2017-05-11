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
SCION_ADDR_LEN = 4 + (MAX_HOST_ADDR_LEN + 1) + 2  # isd_as + Addr(+type) + Port
FILTER_CMD_LEN = 3 * SCION_ADDR_LEN + 2  # (src + dst + hop) + l4 + options
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
ALLOWED_DIRECTIONS = ['ingress', 'egress']
ALLOWED_L4_PROTOS = ['scmp', 'tcp', 'udp', 'ssp']
ALLOWED_FILTER_LEVELS = ['isd', 'as', 'addr', 'port']
MAX_FILTERS_PER_L4 = 255
COMMIT_COMMAND = 'commit'
HELP_COMMAND = 'help'


class Filter(object):
    """
    Stores fields of a filter command after parsing it. And allows packing
    the fields into binary command(s) that can then be sent to libfilter.
    """

    @classmethod
    def print_help(cls):
        print('''
The following is the filter command format:
filter_mode direction l4_protocol [src_spec] [dst_spec] [hop_spec])

Where,
    filter_mode = accept/reject
    direction   = ingress/egress
    l4_protocol = scmp/tcp/udp/ssp
    src_spec    = src [not] [<level>] <node>
    dst_spec    = dst [not] [<level>] <node>
    hop_spec    = hop [not] [<level>] <node>

Note:
    If src_spec/dst_spec/hop_spec is absent, then the filter does not
    match src/dst/hop (respectively) of packets while filtering

    <node> should be a SCION node present in the topology (eg. bs1-11-1)

    <level> is the level at which filtering should happen wrt the node:
    Following are the allowed values for it:
    isd/as/addr/port(default)

Examples:
    reject egress tcp
    reject ingress udp src not isd bs1-11-1
    accept egress ssp dst as ps1-11-1 hop not sb1-11-1
    accept ingress scmp src addr bs1-11-1 dst port ps1-12-1 hop not er1-12er1-11
''')

    @classmethod
    def from_command(cls, command):
        """
        Returns a Filter object with the fields specified by the command.
        """
        args = command.split()
        inst = cls()
        try:
            inst._filter_mode = args.pop(0)
            assert inst._filter_mode in ALLOWED_FILTER_MODES
            inst._direction = args.pop(0)
            assert inst._direction in ALLOWED_DIRECTIONS
            inst._l4_protocol = args.pop(0)
            assert inst._l4_protocol in ALLOWED_L4_PROTOS
            inst._src, inst._src_negated, inst._src_level = \
                cls.parse_addr_pattern('src', args)
            inst._dst, inst._dst_negated, inst._dst_level = \
                cls.parse_addr_pattern('dst', args)
            inst._hop, inst._hop_negated, inst._hop_level = \
                cls.parse_addr_pattern('hop', args)
            assert len(args) == 0
        except Exception as e:
            print(e)
            sys.exit(1)
        return inst

    @classmethod
    def parse_addr_pattern(cls, node_type, args):
        node_name = ''
        pattern_negated = False
        filter_level = 'port'
        if args == [] or args[0] != node_type:
            return (node_name, pattern_negated, filter_level)
        try:
            args.pop(0)
            arg = args.pop(0)
            if arg == 'not':
                pattern_negated = True
                arg = args.pop(0)
            if arg in ALLOWED_FILTER_LEVELS:
                filter_level = arg
                arg = args.pop(0)
            node_name = arg
        except Exception as e:
            print(e)
            sys.exit(1)
        return (node_name, pattern_negated, filter_level)

    def pack(self):
        """
        Returns a bytes object containing all the filters represented by this
        instance of the Filter.
        """
        try:
            l4_protocol_num = L4_PROTOCOL_NUM[self._l4_protocol]
            srcs = self.pack_addr_patterns(self._src, self._src_level)
            dsts = self.pack_addr_patterns(self._dst, self._dst_level)
            hops = self.pack_addr_patterns(self._hop, self._hop_level)
            options = self.pack_options()
        except Exception as e:
            print(e)
            sys.exit(1)

        filters = bytearray()
        for src in srcs:
            for dst in dsts:
                for hop in hops:
                    filters.append(l4_protocol_num)
                    filters += src
                    filters += dst
                    filters += hop
                    filters.append(options)
        return bytes(filters)

    def pack_addr_patterns(self, node, level):
        if node == '':
            return [bytes(SCION_ADDR_LEN)]

        addr_pattern = bytearray(SCION_ADDR_LEN)
        offset = 0

        # Packing ISD and AS of the node into the address pattern
        svc_type = node[:2]
        assert svc_type in SERVICE_TYPES
        isd_as_num = node.split(svc_type)[1].split('-')
        isd_id = int(isd_as_num[0])
        as_id = 0 if level == 'isd' else int(isd_as_num[1])
        isd_as = ISD_AS.from_values(isd_id, as_id).int()
        struct.pack_into('!I', addr_pattern, offset, isd_as)
        offset += ISD_AS.LEN
        if level in ['isd', 'as']:
            return [bytes(addr_pattern)]

        # Packing addr(s) of the node into the address pattern(s)
        addr_patterns = []
        addrs, ports = self.get_node_addrs_and_ports(node, svc_type,
                                                     isd_id, as_id)
        for i in range(len(addrs)):
            tmp_addr_pattern = bytearray(bytes(addr_pattern))
            addr = addrs[i].split('/')[0]
            port = 0 if level == 'addr' else int(ports[i])
            try:
                addr = ipaddress.ip_address(addr)
                addr_type = IP_ADDRESS_NUM[addr.version]
                addr = addr.packed
            except:
                addr = struct.pack('!H', int(addr))
                addr_type = AddrType.SVC
            struct.pack_into('B', tmp_addr_pattern, offset, addr_type)
            tmp_addr_pattern[(offset + 1):(offset + 1 + len(addr))] = addr
            struct.pack_into('!H', tmp_addr_pattern,
                             offset + 1 + MAX_HOST_ADDR_LEN, port)
            addr_patterns += [bytes(tmp_addr_pattern)]
        return addr_patterns

    def get_node_addrs_and_ports(self, node, svc_type, isd_id, as_id):
        topo_file = os.path.join(PROJECT_ROOT,
                                 GEN_PATH,
                                 'ISD{}/AS{}'.format(isd_id, as_id),
                                 node,
                                 TOPO_FILE)
        stream = open(topo_file, "r")
        topology = next(yaml.load_all(stream))
        svc_type_full = SERVICE_ALIAS[svc_type]
        node_topo = topology[svc_type_full][node]
        # TODO: Change this is to read in multiple addresses/ports in future
        addrs = [node_topo['Addr']]
        ports = [node_topo['Port']]
        if 'Interface' in node_topo:
            addrs += [node_topo['Interface']['Addr']]
            ports += [node_topo['Interface']['UdpPort']]
        return (addrs, ports)

    def pack_options(self):
        options = 0
        if self._filter_mode == 'accept':
            options |= FILTER_NEGATED
        if self._direction == 'egress':
            options |= EGRESS
        if self._src_negated:
            options |= SRC_NEGATED
        if self._dst_negated:
            options |= DST_NEGATED
        if self._hop_negated:
            options |= HOP_NEGATED
        return options


def send_filters(header, payload):
    # Create a connection with libfilter
    try:
        port = SCION_FILTER_CMD_PORT
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.connect(('', port))
        logging.info("Client connected to libfilter")
    except Exception as e:
        logging.error(e)
        logging.error("Connection to libfilter failed")
        sock.close()
        sys.exit(1)

    # Send the filter header and payload
    try:
        sock.send(header)
        sock.send(payload)
        logging.info("Sent the filters successfully to libfilter")
    except Exception as e:
        logging.error(e)
        logging.error("Failed to send the filters to libfilter")
        sock.close()
        sys.exit(1)
    sock.close()
    logging.info("Closed down the client")


def main():
    # Initialize the filter client
    header = bytearray()
    payload = bytearray()
    l4_filter_count = {}
    for l4 in ALLOWED_L4_PROTOS:
        l4_filter_count[l4] = 0
    logging.info("Initialized the filter client")
    print("Started the filter client.\n"
          "Enter filter commands one per line.\n"
          "Type 'help' for filter command format info.\n"
          "Type 'commit' when you are done entering all the commands.")

    # Read in commands and generate the batch filter payload
    while True:
        cmd = input()
        if cmd == COMMIT_COMMAND:
            logging.info("Finished reading filter commands")
            break
        if cmd == HELP_COMMAND:
            Filter.print_help()
            continue
        # Generate binary filter(s) from the command and check their counts
        filter = Filter.from_command(cmd)
        l4 = filter._l4_protocol
        packed_filters = filter.pack()
        num_filters = len(packed_filters) // FILTER_CMD_LEN
        if l4_filter_count[l4] + num_filters > MAX_FILTERS_PER_L4:
            logging.error("Neglecting filter(s): limit exceeded for %d", l4)
            sys.exit(1)
        payload += packed_filters
        l4_filter_count[l4] += num_filters

    # Generate the batch filter header
    for l4 in ALLOWED_L4_PROTOS:
        header.append(l4_filter_count[l4])

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
