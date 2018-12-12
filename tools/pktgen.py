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
:mod:`pktgen` --- SCION packet generator
===========================================
"""
# Stdlib
import argparse
import logging
import time
import random as rand

# SCION
from lib.defines import LINE_LEN
from lib.log import init_logging
from lib.main import main_wrapper
from lib.packet.host_addr import haddr_parse_interface
from lib.packet.packet_base import PayloadRaw
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.socket import UDPSocket
from integration.base_cli_srv import TestClientBase

SRC_PORT = 3001
DST_PORT = 3000


class PktGen(TestClientBase):
    # FIXME(kormat): TestClientBase doesn't really offer too much that PktGen needs. It mostly just
    # uses `_get_path()`, `_build_pkt()` and `_create_l4_hdr()` from there. When `lib.app` can
    # easily cover these cases, then we should just drop the inheritance.
    def __init__(self, *args, size=0, **kwargs):
        super().__init__(*args, **kwargs)
        self.size = size
        self.bytes_sent = 0
        self.start = None

    def run(self, count, wait_time):
        self.sent = 0
        spkt = self._build_pkt()
        raw = spkt.pack()
        overlay_dest, overlay_port = str(self.first_hop[0]), self.first_hop[1]
        logging.debug("Sending (via %s:%s):\n%s", overlay_dest, overlay_port, spkt)
        logging.debug(self.path_meta)
        wait_time = wait_time / 1000.0
        self.start = time.time()
        while not count or self.sent < count:
            self.sock.send(raw, (overlay_dest, overlay_port))
            self.sent += 1
            time.sleep(wait_time)
        self._shutdown()

    def random_run(self, count, lambd, number):
        rand.seed()
        self.sent = 0

        packets = []
        for i in range(0, number):
            spkt = self._build_pkt()
            spkt.set_payload(self._create_payload(spkt, True))
            spkt.update()
            raw = spkt.pack()
            packets.append(raw)

        overlay_dest, overlay_port = str(self.first_hop[0]), self.first_hop[1]
        logging.debug("Sending (via %s:%s)", overlay_dest, overlay_port)
        logging.debug(self.path_meta)
        self.start = time.time()

        while not count or self.sent < count:
            packet = packets[rand.randint(0, number - 1)]
            self.sock.send(packet, (overlay_dest, overlay_port))
            self.sent += 1
            self.bytes_sent += len(packet)
            if lambd:
                time.sleep(rand.expovariate(lambd))

        self._shutdown()

    def _create_socket(self, addr):
        # Use UDPSocket directly to bypass the overhead of the dispatcher.
        return UDPSocket(bind=(str(addr.host), SRC_PORT, ""), addr_type=addr.host.TYPE)

    def _create_payload(self, spkt, randlen=False):
        data = b"ping " + self.data
        hdr_len = (spkt.cmn_hdr.hdr_len * LINE_LEN) + len(spkt.l4_hdr)
        min_size = hdr_len + len(data)
        if randlen:
            mean = (self.path_meta.p.mtu - min_size) / 2
            mu = mean + min_size
            sigma = mean / 3
            self.size = int(rand.gauss(mu, sigma))
        if not self.size or self.size > self.path_meta.p.mtu:
            self.size = self.path_meta.p.mtu
        if self.size < min_size:
            self.size = min_size
        pld_len = self.size - hdr_len
        return self._gen_padded_pld(data, pld_len)

    def _gen_padded_pld(self, data, pld_len):
        padding = pld_len - len(data)
        return PayloadRaw(data + bytes(padding))

    def _handle_response(self, _):
        raise NotImplementedError


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--loglevel', default="INFO",
                        help='Console logging level (Default: %(default)s)')
    parser.add_argument('-c', '--count', default=1, type=int,
                        help='Number of packets to send. 0 means unlimited.')
    parser.add_argument('-s', '--size', default=0, type=int,
                        help='Size of packets to send. 0 means use the MTU of the path.')
    parser.add_argument('-w', '--wait', default=0, type=float,
                        help='Wait time in milliseconds after a packet has been sent.')
    parser.add_argument('-r', '--random', action='store_true',
                        help='Run with randomized wait time and packet size')
    parser.add_argument('-la', '--lambd', default=50, type=int,
                        help='Number of packets that are sent in average per second. '
                             '0 means that as many packets as possible are sent.'
                             ' Only used with -r flag')
    parser.add_argument('-n', '--number', default=1000, type=int,
                        help='Number of random sized packets to be used. Only used with -r flag.'
                             '(Default: %(default)s)')
    parser.add_argument('src_ia', help='Src ISD-AS')
    parser.add_argument('src_addr', help='Src IP')
    parser.add_argument('dst_ia', help='Dst ISD-AS')
    parser.add_argument('dst_addr', help='Dst IP')
    args = parser.parse_args()
    init_logging("logs/pktgen", console_level=args.loglevel)
    src = SCIONAddr.from_values(ISD_AS(args.src_ia),
                                haddr_parse_interface(args.src_addr))
    dst = SCIONAddr.from_values(ISD_AS(args.dst_ia),
                                haddr_parse_interface(args.dst_addr))
    gen = PktGen(b"data", src, dst, DST_PORT, size=args.size)

    if args.random and (args.wait or args.size):
        logging.warning("Flags -w and -s are not used in random mode. See -h for help.")
    elif not args.random and (args.lambd != 50 or args.number != 1000):
        logging.warning("Flags -la and -n are not used in performance mode. See -h for help.")

    try:
        if args.random:
            gen.random_run(args.count, args.lambd, args.number)
        else:
            gen.run(args.count, args.wait)
    except KeyboardInterrupt:
        pass
    total = time.time() - gen.start

    if args.random:
        logging.info("Sent %d bytes in %d packets in %.3fs (%d pps, %d bps)", gen.bytes_sent,
                     gen.sent, total, gen.sent / total, (gen.bytes_sent * 8) / total)
    else:
        logging.info("Sent %d %dB packets in %.3fs (%d pps, %d bps)", gen.sent, gen.size,
                     total, gen.sent / total, (gen.sent * gen.size * 8) / total)


if __name__ == "__main__":
    main_wrapper(main)
