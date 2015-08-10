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
import logging
import random
import socket
import sys
import threading
import time
import unittest
from ipaddress import IPv4Address

# SCION
from endhost.sciond import SCIOND_API_HOST, SCIOND_API_PORT, SCIONDaemon
from lib.defines import IPV4BYTES, SCION_BUFLEN, SCION_UDP_EH_DATA_PORT
from lib.packet.opaque_field import InfoOpaqueField, OpaqueFieldType as OFT
from lib.packet.path import CorePath, CrossOverPath, EmptyPath, PeerPath
from lib.packet.scion import SCIONPacket
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.log import init_logging
from lib.util import Raw
from lib.thread import kill_self, thread_safety_net

saddr = IPv4Address("127.1.19.254")
raddr = IPv4Address("127.2.26.254")
TOUT = 10  # How long wait for response.


def get_paths_via_api(isd, ad):
    """
    Test local API.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 5005))
    msg = b'\x00' + ISD_AD(isd, ad).pack()
    logging.info("Sending path request to local API.")
    sock.sendto(msg, (SCIOND_API_HOST, SCIOND_API_PORT))

    data = Raw(sock.recvfrom(SCION_BUFLEN)[0], "Path response")
    if len(data) == 0:
        logging.critical("Empty response from local api.")
        kill_self()
    paths_hops = []
    while len(data) > 0:
        path_len = data.pop(1) * 8
        info = InfoOpaqueField(data.get(InfoOpaqueField.LEN))
        if not path_len:  # Shouldn't happen.
            path = EmptyPath()
        elif info.info == OFT.TDC_XOVR:
            path = CorePath(data.pop(path_len))
        elif info.info == OFT.NON_TDC_XOVR:
            path = CrossOverPath(data.pop(path_len))
        elif info.info == OFT.INTRATD_PEER or info.info == OFT.INTERTD_PEER:
            path = PeerPath(data.pop(path_len))
        else:
            logging.critical("Can not parse path: Unknown type %x", info.info)
            kill_self()
        hop = IPv4Address(data.pop(IPV4BYTES))
        paths_hops.append((path, hop))
    sock.close()
    return paths_hops


class Ping(object):
    """
    Simple ping app.
    """
    def __init__(self, src, dst):
        self.src = src
        self.dst = dst
        self.pong_received = False
        topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                     (src.isd, src.isd, src.ad))
        self.sd = SCIONDaemon.start(saddr, topo_file, True)  # API on
        self.get_path()

    def get_path(self):
        logging.info("Sending PATH request for (%d, %d)",
                     self.dst.isd, self.dst.ad)
        # Get paths through local API.
        paths_hops = get_paths_via_api(self.dst.isd, self.dst.ad)
        (self.path, self.hop) = paths_hops[0]

    def run(self):
        self.send()
        self.recv()

    def send(self):
        dst = SCIONAddr.from_values(self.dst.isd, self.dst.ad, raddr)
        spkt = SCIONPacket.from_values(self.sd.addr, dst, b"ping", self.path)
        (next_hop, port) = self.sd.get_first_hop(spkt)
        assert next_hop == self.hop

        logging.info("Sending packet: \n%s\nFirst hop: %s:%s",
                     spkt, next_hop, port)
        self.sd.send(spkt, next_hop, port)

    def recv(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((str(saddr), SCION_UDP_EH_DATA_PORT))
        packet, _ = sock.recvfrom(SCION_BUFLEN)
        if SCIONPacket(packet).payload == b"pong":
            logging.info('%s: pong received.', saddr)
            self.pong_received = True
        sock.close()
        self.sd.stop()


class Pong(object):
    """
    Simple pong app.
    """
    def __init__(self, dst):
        self.dst = dst
        self.ping_received = False
        topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                     (self.dst.isd, self.dst.isd, self.dst.ad))
        self.sd = SCIONDaemon.start(raddr, topo_file)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((str(raddr), SCION_UDP_EH_DATA_PORT))

    def run(self):
        packet, _ = self.sock.recvfrom(SCION_BUFLEN)
        spkt = SCIONPacket(packet)
        if spkt.payload == b"ping":
            # Reverse the packet and send "pong".
            logging.info('%s: ping received, sending pong.', raddr)
            self.ping_received = True
            spkt.hdr.reverse()
            spkt.payload = b"pong"
            (next_hop, port) = self.sd.get_first_hop(spkt)
            self.sd.send(spkt, next_hop, port)
        self.sock.close()
        self.sd.stop()


class TestSCIONDaemon(unittest.TestCase):
    """
    Unit tests for sciond.py. For this test a infrastructure must be running.
    """

    def test(self, sources, destinations):
        """
        Testing function. Creates an instance of SCIONDaemon, then verifies path
        requesting, and finally sends packet through SCION. Sender is 127.1.19.1
        placed in every AD from `sources`, and receiver is 127.2.26.1 from
        every AD from `destinations`.
        """
        for src in sources:
            for dst in destinations:
                if src != dst:
                    logging.info("Testing: %s -> %s", src, dst)
                    src = ISD_AD(src[0], src[1])
                    dst = ISD_AD(dst[0], dst[1])
                    pong_app = Pong(dst)
                    threading.Thread(
                        target=thread_safety_net, args=(pong_app.run,),
                        name="E2E.pong_app", daemon=True).start()
                    ping_app = Ping(src, dst)
                    threading.Thread(
                        target=thread_safety_net, args=(ping_app.run,),
                        name="E2E.ping_app", daemon=True).start()
                    for _ in range(TOUT * 10):
                        time.sleep(0.1)
                        if pong_app.ping_received and ping_app.pong_received:
                            break
                    self.assertTrue(pong_app.ping_received)
                    self.assertTrue(ping_app.pong_received)

if __name__ == "__main__":
    init_logging("../../logs/end2end.log", console=True)
    if len(sys.argv) == 3:
        isd, ad = sys.argv[1].split(',')
        sources = [(int(isd), int(ad))]
        isd, ad = sys.argv[2].split(',')
        destinations = [(int(isd), int(ad))]
    else:
        # You can specify src and dst by giving 'sISD,sAD dISD,dAD' as
        # the arguments. E.g.: python3 end2end_test.py 1,19 2,26
        sources = [(1, 17), (1, 19), (1, 10), (2, 25)]
        sources += [(2, 26), (1, 14), (1, 18)]
        destinations = sources[:]
        # Randomize order of the connections.
        random.shuffle(sources)
        random.shuffle(destinations)

    TestSCIONDaemon().test(sources, destinations)
