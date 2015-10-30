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
import logging
import random
import sys
import threading
import time
import unittest

# SCION
from endhost.sciond import SCIOND_API_HOST, SCIOND_API_PORT, SCIONDaemon
from lib.defines import GEN_PATH
from lib.log import init_logging, log_exception
from lib.packet.host_addr import haddr_get_type, haddr_parse
from lib.packet.opaque_field import InfoOpaqueField
from lib.packet.packet_base import PayloadRaw
from lib.packet.path import CorePath, CrossOverPath, EmptyPath, PeerPath
from lib.packet.scion import SCIONL4Packet, build_base_hdrs
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from lib.packet.scion_udp import SCIONUDPHeader
from lib.socket import UDPSocket
from lib.thread import kill_self, thread_safety_net
from lib.types import AddrType, OpaqueFieldType as OFT
from lib.util import Raw, handle_signals

saddr = haddr_parse("IPV4", "127.1.19.254")
raddr = haddr_parse("IPV4", "127.2.26.254")
TOUT = 10  # How long wait for response.


def get_paths_via_api(isd, ad):
    """
    Test local API.
    """
    sock = UDPSocket(bind=("127.0.0.1", 0), addr_type=AddrType.IPV4)
    msg = b'\x00' + ISD_AD(isd, ad).pack()

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
    while len(data) > 0:
        path_len = data.pop(1) * 8
        if not path_len:
            return [(EmptyPath(), haddr_parse("IPV4", "0.0.0.0"))]
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
        data.pop(2)
        interface_count = data.pop(1)
        data.pop(interface_count * 5)  # interface list unused here
    sock.close()
    return paths_hops


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
        conf_dir = "%s/ISD%d/AD%d/common" % (GEN_PATH, src.isd, src.ad)
        # Local api on, random port:
        self.sd = SCIONDaemon.start(
            conf_dir, saddr, run_local_api=True, port=0)
        self.get_path()
        self.sock = UDPSocket(bind=(str(saddr), 0, "Ping App"),
                              addr_type=AddrType.IPV4)

    def get_path(self):
        logging.info("Sending PATH request for (%d, %d)",
                     self.dst.isd, self.dst.ad)
        # Get paths through local API.
        paths_hops = get_paths_via_api(self.dst.isd, self.dst.ad)
        (self.path, self.hop) = paths_hops[0]
        if isinstance(self.path, EmptyPath):
            self.hop = raddr

    def run(self):
        self.send()
        self.recv()

    def send(self):
        dst_addr = SCIONAddr.from_values(self.dst.isd, self.dst.ad, raddr)
        src_addr = SCIONAddr.from_values(self.src.isd, self.src.ad, saddr)
        cmn_hdr, addr_hdr = build_base_hdrs(src_addr, dst_addr)
        payload = PayloadRaw(b"ping " + self.token)
        udp_hdr = SCIONUDPHeader.from_values(
            src_addr, self.sock.port, dst_addr, self.dport, payload)
        spkt = SCIONL4Packet.from_values(
            cmn_hdr, addr_hdr, self.path, [], udp_hdr, payload)
        (next_hop, port) = self.sd.get_first_hop(spkt)
        assert next_hop == self.hop

        logging.info("Sending packet: \n%s\nFirst hop: %s:%s",
                     spkt, next_hop, port)
        self.sd.send(spkt, next_hop, port)

    def recv(self):
        packet = self.sock.recv()[0]
        spkt = SCIONL4Packet(packet)
        payload = spkt.get_payload()
        pong = PayloadRaw(b"pong " + self.token)
        if payload == pong:
            logging.info('%s:%d: pong received.', saddr, self.sock.port)
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
        conf_dir = "%s/ISD%d/AD%d/common" % (
            GEN_PATH, self.dst.isd, self.dst.ad)
        self.sd = SCIONDaemon.start(conf_dir, raddr)  # API off, standard port.
        self.sock = UDPSocket(bind=(str(raddr), 0, "Pong App"),
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
            logging.info('%s:%d: ping received, sending pong.', raddr,
                         self.sock.port)
            self.ping_received = True
            spkt.reverse()
            spkt.set_payload(PayloadRaw(b"pong " + self.token))
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
        thread = threading.current_thread()
        thread.name = "E2E.MainThread"
        failures = 0
        for src_id in sources:
            for dst_id in destinations:
                logging.info("Testing: %s -> %s", src_id, dst_id)
                src = ISD_AD(*src_id)
                dst = ISD_AD(*dst_id)
                token = (
                    "%s-%s<->%s-%s" % (src[0], src[1], dst[0],
                                       dst[1])
                ).encode("UTF-8")
                pong_app = Pong(dst, token)
                threading.Thread(
                    target=thread_safety_net, args=(pong_app.run,),
                    name="E2E.pong_app", daemon=True).start()
                ping_app = Ping(src, dst, pong_app.sock.port, token)
                threading.Thread(
                    target=thread_safety_net, args=(ping_app.run,),
                    name="E2E.ping_app", daemon=True).start()
                for _ in range(TOUT * 10):
                    time.sleep(0.1)
                    if pong_app.ping_received and ping_app.pong_received:
                        break
                else:
                    logging.error("Test timed out")
                    failures += 1
                self.assertTrue(pong_app.ping_received)
                self.assertTrue(ping_app.pong_received)
        sys.exit(failures)

if __name__ == "__main__":
    init_logging("logs/end2end.log", console=True)
    handle_signals()
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

    try:
        TestSCIONDaemon().test(sources, destinations)
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
