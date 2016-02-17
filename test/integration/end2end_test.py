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
:mod:`end2end_test` --- SCION end2end tests
===========================================
"""
# Stdlib
import argparse
import copy
import logging
import os
import random
import struct
import sys
import threading
import time

# SCION
from endhost.sciond import SCIOND_API_HOST, SCIOND_API_PORT, SCIONDaemon
from lib.defines import AS_LIST_FILE, GEN_PATH
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import (
    haddr_get_type,
    haddr_parse,
    haddr_parse_interface,
)
from lib.packet.opaque_field import InfoOpaqueField
from lib.packet.packet_base import PayloadRaw
from lib.packet.path import CorePath, CrossOverPath, EmptyPath, PeerPath
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.scion_udp import SCIONUDPHeader
from lib.socket import UDPSocket
from lib.thread import kill_self, thread_safety_net
from lib.types import AddrType, OpaqueFieldType as OFT
from lib.util import Raw, handle_signals, load_yaml_file

TOUT = 10  # How long wait for response.


def get_paths_via_api(addr):
    """
    Test local API.
    """
    sock = UDPSocket(bind=("127.0.0.1", 0), addr_type=AddrType.IPV4)
    msg = b'\x00' + addr.isd_as.pack()

    for _ in range(5):
        logging.info("Sending path request to local API.")
        sock.send(msg, (SCIOND_API_HOST, SCIOND_API_PORT))
        data = Raw(sock.recv()[0], "Path response")
        if data:
            break
        logging.warning("Empty response from local api.")
    else:
        logging.critical("Unable to get path from local api.")
        kill_self()

    paths_hops = []
    iflists = []
    while len(data) > 0:
        path_len = data.pop(1) * 8
        if not path_len:
            return [(EmptyPath(), haddr_parse("IPV4", "0.0.0.0"))], [[]]
        info = InfoOpaqueField(data.get(InfoOpaqueField.LEN))
        if info.info == OFT.CORE:
            path = CorePath(data.pop(path_len))
        elif info.info == OFT.SHORTCUT:
            path = CrossOverPath(data.pop(path_len))
        elif info.info in [OFT.INTRA_ISD_PEER, OFT.INTER_ISD_PEER]:
            path = PeerPath(data.pop(path_len))
        else:
            logging.critical("Can not parse path: Unknown type %x", info.info)
            kill_self()
        haddr_type = haddr_get_type("IPV4")
        hop = haddr_type(data.get(haddr_type.LEN))
        data.pop(len(hop))
        paths_hops.append((path, hop))
        data.pop(2)  # port number, unused here
        data.pop(2)  # MTU, unused here
        ifcount = data.pop(1)
        ifs = []
        if ifcount:
            for i in range(ifcount):
                isd_as = ISD_AS(data.pop(ISD_AS.LEN))
                ifid = struct.unpack("H", data.pop(2))[0]
                ifs.append((isd_as, ifid))
        iflists.append(ifs)
    sock.close()
    return paths_hops, iflists


class Ping(object):
    """
    Simple ping app.
    """
    def __init__(self, src, dst, dport, token):
        self.src = src
        self.dst = dst
        self.dport = dport
        self.token = token
        self.pong_received = False
        conf_dir = "%s/ISD%d/AS%d/endhost" % (
            GEN_PATH, src.isd_as[0], src.isd_as[1])
        # Local api on, random port:
        self.sd = SCIONDaemon.start(
            conf_dir, self.src.host, run_local_api=True, port=0)
        self.get_path()
        self.sock = UDPSocket(bind=(str(self.src.host), 0, "Ping App"),
                              addr_type=AddrType.IPV4)

    def get_path(self):
        logging.info("Sending PATH request for %s", self.dst)
        # Get paths through local API.
        paths_hops, iflists = get_paths_via_api(self.dst)
        self.path, self.hop = paths_hops[0]
        if isinstance(self.path, EmptyPath):
            self.hop = self.dst.host
        self.iflist = iflists[0]

    def run(self):
        self.send()
        self.recv()

    def send(self):
        cmn_hdr, addr_hdr = build_base_hdrs(self.src, self.dst)
        payload = PayloadRaw(b"ping " + self.token)
        udp_hdr = SCIONUDPHeader.from_values(
            self.src, self.sock.port, self.dst, self.dport, payload)
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, self.path, [], udp_hdr, payload)
        next_hop, port = self.sd.get_first_hop(spkt)
        assert next_hop is not None
        assert next_hop == self.hop
        logging.info("Sending packet via (%s:%s):\n%s", next_hop, port, spkt)
        if self.iflist:
            logging.info("Interfaces: %s", ", ".join(
                ["%s:%s" % ifentry for ifentry in self.iflist]))
        self.sd.send(spkt, next_hop, port)

    def recv(self):
        packet = self.sock.recv()[0]
        spkt = SCIONL4Packet(packet)
        payload = spkt.get_payload()
        pong = PayloadRaw(b"pong " + self.token)
        if payload == pong:
            logging.info('%s:%d: pong received.', self.src.host, self.sock.port)
            self.pong_received = True
        else:
            logging.error("Unexpected payload received: %s (expected: %s)",
                          payload, pong)
            kill_self()
        self.sock.close()
        self.sd.stop()


class Pong(object):
    """
    Simple pong app.
    """
    def __init__(self, dst, token):
        self.dst = dst
        self.token = token
        self.ping_received = False
        conf_dir = "%s/ISD%d/AS%d/endhost" % (
            GEN_PATH, self.dst.isd_as[0], self.dst.isd_as[1])
        # API off, standard port.
        self.sd = SCIONDaemon.start(conf_dir, self.dst.host)
        self.sock = UDPSocket(bind=(str(self.dst.host), 0, "Pong App"),
                              addr_type=AddrType.IPV4)

    def get_local_port(self):
        return self.sock.get_port()

    def run(self):
        packet = self.sock.recv()[0]
        spkt = SCIONL4Packet(packet)
        payload = spkt.get_payload()
        ping = PayloadRaw(b"ping " + self.token)
        if payload == ping:
            # Reverse the packet and send "pong".
            logging.info('%s:%d: ping received, sending pong.',
                         self.dst.host, self.sock.port)
            self.ping_received = True
            spkt.reverse()
            spkt.set_payload(PayloadRaw(b"pong " + self.token))
            next_hop, port = self.sd.get_first_hop(spkt)
            assert next_hop is not None
            logging.info("Replying with (via %s:%s):\n%s", next_hop, port, spkt)
            self.sd.send(spkt, next_hop, port)
        self.sock.close()
        self.sd.stop()


class TestSCIONDaemon(object):
    """
    Unit tests for sciond.py. For this test a infrastructure must be running.
    """
    def __init__(self, client, server, sources, destinations):
        self.client_ip = haddr_parse_interface(client)
        self.server_ip = haddr_parse_interface(server)
        self.src_ias = sources
        self.dst_ias = destinations
        self.run()

    def run(self):
        """
        Testing function. Creates an instance of SCIONDaemon, then verifies path
        requesting, and finally sends packet through SCION. Sender is placed in
        every AS from `sources`, and receiver is from every AS from
        `destinations`.
        """
        thread = threading.current_thread()
        thread.name = "E2E.MainThread"
        for src_ia in self.src_ias:
            for dst_ia in self.dst_ias:
                self._run_test(src_ia, dst_ia)

    def _run_test(self, src_ia, dst_ia):
        logging.info("Testing: %s -> %s", src_ia, dst_ia)
        src_addr = SCIONAddr.from_values(src_ia, self.client_ip)
        dst_addr = SCIONAddr.from_values(dst_ia, self.server_ip)
        token = ("%s<->%s" % (src_addr, dst_addr)).encode("UTF-8")
        pong_app = Pong(dst_addr, token)
        threading.Thread(
            target=thread_safety_net, args=(pong_app.run,),
            name="E2E.pong_app", daemon=True).start()
        ping_app = Ping(src_addr, dst_addr, pong_app.sock.port, token)
        threading.Thread(
            target=thread_safety_net, args=(ping_app.run,),
            name="E2E.ping_app", daemon=True).start()
        for _ in range(TOUT * 10):
            time.sleep(0.1)
            if pong_app.ping_received and ping_app.pong_received:
                break
        else:
            logging.error("Test timed out")
            sys.exit(1)


def _load_as_list():
    as_dict = load_yaml_file(os.path.join(GEN_PATH, AS_LIST_FILE))
    as_list = []
    for as_str in as_dict.get("Non-core", []) + as_dict.get("Core", []):
        as_list.append(ISD_AS(as_str))
    return as_list


def _parse_locs(as_str, as_list):
    if as_str:
        return [ISD_AS(as_str)]
    copied = copy.copy(as_list)
    random.shuffle(copied)
    return copied


def main():
    handle_signals()
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--client', help='Client address')
    parser.add_argument('-s', '--server', help='Server address')
    parser.add_argument('-m', '--mininet', action='store_true',
                        help="Running under mininet")
    parser.add_argument('src_ia', nargs='?', help='Src isd-as')
    parser.add_argument('dst_ia', nargs='?', help='Dst isd-as')
    args = parser.parse_args()
    init_logging("logs/end2end", console_level=logging.DEBUG)

    if not args.client:
        args.client = "169.254.0.2" if args.mininet else "127.0.0.2"
    if not args.server:
        args.server = "169.254.0.3" if args.mininet else "127.0.0.3"
    as_list = _load_as_list()
    srcs = _parse_locs(args.src_ia, as_list)
    dsts = _parse_locs(args.dst_ia, as_list)

    TestSCIONDaemon(args.client, args.server, srcs, dsts)


if __name__ == "__main__":
    main_wrapper(main)
