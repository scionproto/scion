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
:mod:`bandwidth_test` --- Bandwidth tests
=========================================
"""
# Stdlib
import logging
import socket
import sys
import threading
import time
import unittest

# SCION
from sciond.sciond import SCIONDaemon
from lib.defines import GEN_PATH
from lib.log import init_logging, log_exception
from lib.packet.host_addr import haddr_parse
from lib.packet.packet_base import PayloadRaw
from lib.socket import UDPSocket
from lib.thread import thread_safety_net
from lib.types import AddrType
from lib.util import handle_signals

PACKETS_NO = 1000
PAYLOAD_SIZE = 1300
# Time interval between transmission of two consecutive packets
SLEEP = 0.0001


class TestBandwidth(unittest.TestCase):
    """
    Bandwidth testing. For this test a infrastructure must be running.
    """

    def receiver(self, rcv_sock):
        """
        Receives the packet sent by test() method.
        Measures goodput and packets loss ratio.
        """
        i = 0
        start = None
        timeout = 1
        while i < PACKETS_NO:
            try:
                packet, _ = rcv_sock.recv()
            except socket.timeout:
                logging.error("Timed out after %d packets", i)
                # Account for the timeout interval itself
                start += timeout
                break
            if i == 0:
                # Allows us to wait as long as necessary for the first packet,
                # and then have timeouts for later packets.
                rcv_sock.sock.settimeout(timeout)
                start = time.time()
            i += 1
        duration = time.time() - start

        lost = PACKETS_NO - i
        self.rate = 100*(lost/PACKETS_NO)
        logging.info("Goodput: %.2fKBps Pkts received: %d Pkts lost: %d "
                     "Loss rate: %.2f%%" %
                     ((i*PAYLOAD_SIZE)/duration/1000, i, lost, self.rate))

    def test(self):
        """
        Bandwidth test method. Obtains a path to (2, 26) and sends PACKETS_NO
        packets (each with PAYLOAD_SIZE long payload) to a host in (2, 26).
        """
        addr = haddr_parse("IPV4", "127.1.19.254")
        conf_dir = "%s/ISD1/AD19/endhost" % GEN_PATH
        sender = SCIONDaemon.start(conf_dir, addr)

        paths = sender.get_paths(2, 26)
        self.assertTrue(paths)

        rcv_sock = UDPSocket(bind=("127.2.26.254", 0, "Bw test receiver"),
                             addr_type=AddrType.IPV4)

        logging.info("Starting the receiver.")
        recv_t = threading.Thread(
            target=thread_safety_net, args=(self.receiver, rcv_sock),
            name="BwT.receiver")
        recv_t.start()

        payload = PayloadRaw(b"A" * PAYLOAD_SIZE)
        spkt = sender._build_packet(
            haddr_parse("IPV4", "127.2.26.254"), dst_isd=2, dst_ad=26,
            dst_port=rcv_sock.port, payload=payload, path=paths[0])
        (next_hop, port) = sender.get_first_hop(spkt)
        assert next_hop is not None
        logging.info("Sending %d payload bytes (%d packets x %d bytes )" %
                     (PACKETS_NO * PAYLOAD_SIZE, PACKETS_NO, PAYLOAD_SIZE))
        for _ in range(PACKETS_NO):
            sender.send(spkt, next_hop, port)
            time.sleep(SLEEP)
        logging.info("Sending finished")

        recv_t.join()
        if self.rate < 10.0:
            sys.exit(0)
        else:
            sys.exit(int(self.rate))


if __name__ == "__main__":
    init_logging("logs/bw_test", console_level=logging.DEBUG)
    handle_signals()
    try:
        TestBandwidth().test()
    except SystemExit:
        logging.info("Exiting")
        raise
    except:
        log_exception("Exception in main process:")
        logging.critical("Exiting")
        sys.exit(1)
