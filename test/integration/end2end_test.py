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
from lib.defines import SCION_BUFLEN, SCION_UDP_EH_DATA_PORT
from lib.packet.opaque_field import InfoOpaqueField, OpaqueFieldType as OFT
from lib.packet.path import CorePath, CrossOverPath, EmptyPath, PeerPath
from lib.packet.scion import SCIONPacket
from lib.packet.scion_addr import SCIONAddr, ISD_AD

ping_received = False
pong_received = False
SRC = None
DST = None
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
    print("Sending path request to local API.")
    sock.sendto(msg, (SCIOND_API_HOST, SCIOND_API_PORT))

    data, _ = sock.recvfrom(1024)
    offset = 0
    paths_hops = []
    while offset < len(data):
        path_len = int(data[offset]) * 8
        offset += 1
        raw_path = data[offset:offset+path_len]
        path = None
        info = InfoOpaqueField(raw_path[0:InfoOpaqueField.LEN])
        if not path_len:  # Shouldn't happen.
            path = EmptyPath()
        elif info.info == OFT.TDC_XOVR:
            path = CorePath(raw_path)
        elif info.info == OFT.NON_TDC_XOVR:
            path = CrossOverPath(raw_path)
        elif info.info == OFT.INTRATD_PEER or info.info == OFT.INTERTD_PEER:
            path = PeerPath(raw_path)
        else:
            logging.info("Can not parse path: Unknown type %x", info.info)
        assert path
        offset += path_len
        hop = IPv4Address(data[offset:offset+4])
        offset += 4
        paths_hops.append((path, hop))
    sock.close()
    return paths_hops


def ping_app():
    """
    Simple ping app.
    """
    global pong_received
    topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                 (SRC.isd, SRC.isd, SRC.ad))
    sd = SCIONDaemon.start(saddr, topo_file, True)  # API on
    print("Sending PATH request for (%d, %d)" % (DST.isd, DST.ad))
    # Get paths through local API.
    paths_hops = get_paths_via_api(DST.isd, DST.ad)
    assert paths_hops
    (path, hop) = paths_hops[0]
    # paths = sd.get_paths(2, 26) # Get paths through function call.
    # assert paths

    dst = SCIONAddr.from_values(DST.isd, DST.ad, raddr)
    spkt = SCIONPacket.from_values(sd.addr, dst, b"ping", path)
    (next_hop, port) = sd.get_first_hop(spkt)
    assert next_hop == hop
    print("Sending packet: %s\nFirst hop: %s:%s\n" % (spkt, next_hop, port))
    sd.send(spkt, next_hop, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((str(saddr), SCION_UDP_EH_DATA_PORT))
    packet, _ = sock.recvfrom(SCION_BUFLEN)
    if SCIONPacket(packet).payload == b"pong":
        print('%s: pong received.' % saddr)
        pong_received = True
    sock.close()
    sd.clean()
    print("Leaving ping_app.")


def pong_app():
    """
    Simple pong app.
    """
    global ping_received
    topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                 (DST.isd, DST.isd, DST.ad))
    sd = SCIONDaemon.start(raddr, topo_file)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((str(raddr), SCION_UDP_EH_DATA_PORT))
    packet, _ = sock.recvfrom(SCION_BUFLEN)
    spkt = SCIONPacket(packet)
    if spkt.payload == b"ping":
        # Reverse the packet and send "pong".
        print('%s: ping received, sending pong.' % raddr)
        ping_received = True
        spkt.hdr.reverse()
        spkt.payload = b"pong"
        (next_hop, port) = sd.get_first_hop(spkt)
        sd.send(spkt, next_hop, port)
    sock.close()
    sd.clean()
    print("Leaving pong_app.")


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
        global SRC, DST, ping_received, pong_received
        for src in sources:
            for dst in [x for x in destinations if x != src]:
                if src != dst:
                    SRC = ISD_AD(src[0], src[1])
                    DST = ISD_AD(dst[0], dst[1])
                    threading.Thread(target=ping_app).start()
                    threading.Thread(target=pong_app).start()
                    print("\nTesting:", src, "->", dst)
                    for _ in range(TOUT * 10):
                        time.sleep(0.1)
                        if ping_received and pong_received:
                            break
                    self.assertTrue(ping_received)
                    self.assertTrue(pong_received)
                    ping_received = False
                    pong_received = False

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) == 3:
        isd, ad = sys.argv[1].split(',')
        sources = [(int(isd), int(ad))]
        isd, ad = sys.argv[2].split(',')
        destinations = [(int(isd), int(ad))]
    else:
        print("You can specify src and dst by giving 'sISD,sAD dISD,dAD' as "
              "the arguments. E.g.:\n# python3 end2end_test.py 1,19 2,26")
        sources = [(1, 17), (1, 19), (1, 10), (2, 25)]
        sources += [(2, 26), (1, 14), (1, 18)]
        destinations = sources[:]
        # Randomize order of the connections.
        random.shuffle(sources)
        random.shuffle(destinations)

    TestSCIONDaemon().test(sources, destinations)
