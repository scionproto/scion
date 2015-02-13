"""
end2end_test.py

Copyright 2014 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
from lib.packet.path import (PathType, CorePath, PeerPath, CrossOverPath,
                             EmptyPath, PathBase)
from lib.packet.opaque_field import InfoOpaqueField
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.scion import SCIONPacket
from endhost.sciond import SCIONDaemon, SCIOND_API_HOST, SCIOND_API_PORT
from infrastructure.scion_elem import SCION_UDP_EH_DATA_PORT, BUFLEN
import logging
import time
import unittest
import sys
import socket
import struct
import threading

ping_received = False
pong_received = False


def get_paths_via_api(isd, ad):
    """
    Test local API.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 5005))
    msg = b'\x00' + struct.pack("H", isd) + struct.pack("Q", ad)
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
        if info.info == PathType.CORE:
            path = CorePath(raw_path)
        elif info.info == PathType.CROSS_OVER:
            path = CrossOverPath(raw_path)
        elif info.info == PathType.PEER_LINK:
            path = PeerPath(raw_path)
        elif info.info == PathType.EMPTY:
            path = EmptyPath()
        else:
            logging.info("Can not parse path: Unknown type %x", info.info)
        assert path
        offset += path_len
        hop = IPv4HostAddr(data[offset:offset+4])
        offset += 4
        paths_hops.append((path, hop))
    sock.close()
    return paths_hops


saddr = IPv4HostAddr("127.1.19.254")
raddr = IPv4HostAddr("127.2.26.254")

def ping_app():
    """
    Simple ping app.
    """
    global pong_received
    topo_file = "../topology/ISD1/topologies/ISD:1-AD:19-V:0.json"
    sd = SCIONDaemon.start(saddr, topo_file, True) # API on
    print("Sending PATH request for (2, 26) in 3 seconds")
    time.sleep(3)
    paths_hops = get_paths_via_api(2, 26) # Get paths through local API.
    assert paths_hops
    (path, hop) = paths_hops[0]
    # paths = sd.get_paths(2, 26) # Get paths through function call.
    # assert paths

    spkt = SCIONPacket.from_values(sd.addr, raddr, b"ping", path)
    (next_hop, port) = sd.get_first_hop(spkt)
    assert next_hop == hop
    print("Sending packet: %s\nFirst hop: %s:%s\n" % (spkt, next_hop, port))
    sd.send(spkt, next_hop, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((str(saddr), SCION_UDP_EH_DATA_PORT))
    packet, _ = sock.recvfrom(BUFLEN)
    if SCIONPacket(packet).payload == b"pong":
        print('%s: pong received.' % saddr)
        pong_received = True
    sock.close()

def pong_app():
    """
    Simple pong app.
    """
    global ping_received
    topo_file = "../topology/ISD2/topologies/ISD:2-AD:26-V:0.json"
    sd = SCIONDaemon.start(raddr, topo_file)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((str(raddr), SCION_UDP_EH_DATA_PORT))
    packet, _ = sock.recvfrom(BUFLEN)
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


class TestSCIONDaemon(unittest.TestCase):
    """
    Unit tests for sciond.py. For this test a infrastructure must be running.
    """

    def test(self):
        """
        Testing function. Creates an instance of SCIONDaemon, then verifies path
        requesting, and finally sends packet through SCION. Sender is 127.1.19.1
        placed in ISD:1, AD:19, and receiver is 127.2.26.1 in ISD:2, AD:26.
        """
        threading.Thread(target=ping_app).start()
        threading.Thread(target=pong_app).start()

        time.sleep(4)
        self.assertTrue(ping_received)
        self.assertTrue(pong_received)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
