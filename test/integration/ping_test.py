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
import struct
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
from lib.packet.scion import SCIONPacket, SCIONHeader
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.packet.scion_icmp import SCIONICMPPacket, SCIONICMPType
from SCIONICMPEngine import SCIONICMPEngine

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
    topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                 (SRC.isd, SRC.isd, SRC.ad))
    sd = SCIONDaemon.start(saddr, topo_file, True)  # API on
    print("Sending PATH request for (%d, %d) in 2 seconds" % (DST.isd, DST.ad))
    time.sleep(2)
    # Get paths through local API.
    paths_hops = get_paths_via_api(DST.isd, DST.ad)
    assert paths_hops
    (path, hop) = paths_hops[0]
    # paths = sd.get_paths(2, 26) # Get paths through function call.
    # assert paths

    dst = SCIONAddr.from_values(DST.isd, DST.ad, raddr)
    scion_hdr = SCIONHeader.from_values(sd.addr, dst, path)
    icmp_pkt = SCIONICMPPacket.from_values(sd.addr, scion_hdr, SCIONICMPType.ICMP_ECHO, 0, 0, b"hello world!")
    (next_hop, port) = sd.get_first_hop_from_scion_hdr(icmp_pkt.scion_hdr)

    print("Send packet. Payload: %s" % (icmp_pkt.data, ))
    sd.send(icmp_pkt, next_hop, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((str(saddr), SCION_UDP_EH_DATA_PORT))
    packet, _ = sock.recvfrom(SCION_BUFLEN)
    
    icmp_pkt = SCIONICMPPacket(packet)
    print("Receive Packet. Payload: %s" % (icmp_pkt.data,))

    sock.close()
    sd.clean()
    print("Leaving ping_app.")


def pong_app():
    """
    Simple pong app.
    """

    topo_file = ("../../topology/ISD%d/topologies/ISD:%d-AD:%d.json" %
                 (DST.isd, DST.isd, DST.ad))
    sd = SCIONDaemon.start(raddr, topo_file)
    icmp_engine = SCIONICMPEngine(sd)
    
    # listen for icmp packets
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((str(raddr), SCION_UDP_EH_DATA_PORT))
    packet, _ = sock.recvfrom(SCION_BUFLEN)

    icmp_engine.handle_icmp_pkt(packet)        

    sock.close()
    sd.clean()
    print("Leaving pong_app.")

if __name__ == "__main__":


    SRC = ISD_AD(1, 17)
    DST = ISD_AD(1, 19)
    threading.Thread(target=ping_app).start()
    threading.Thread(target=pong_app).start()
    time.sleep(1)
    

    
