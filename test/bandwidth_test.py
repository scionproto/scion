"""
bandwidth_test.py

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
from endhost.sciond import SCIONDaemon
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.scion import SCIONPacket
from infrastructure.scion_elem import SCION_UDP_EH_DATA_PORT, BUFLEN
import socket
import threading
import time
import unittest
import logging

PACKETS_NO = 1000
PAYLOAD_SIZE = 1300
SLEEP = 0.000005 # Time interval between transmission of two consecutive packets

class TestBandwidth(unittest.TestCase):
    """
    Bandwidth testing. For this test a infrastructure must be running.
    """

    def receiver(self):
        """
        Receives the packet sent by test() method.
        Measures goodput and packets loss ratio.
        """
        rcv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rcv_sock.bind((str("127.2.26.254"), SCION_UDP_EH_DATA_PORT))
        rcv_sock.settimeout(1)
        
        i = 0
        try:
            packet, _ = rcv_sock.recvfrom(BUFLEN)
            i += 1
            start = time.time()
            while i < PACKETS_NO:
                packet, _ = rcv_sock.recvfrom(BUFLEN)
                i += 1
            duration = time.time() - start
        except socket.timeout:
            duration = time.time() - start - 1 # minus timeout
            print("Timeouted - there are lost packets")

        print("Goodput %.2fKBps, loss %.2f\n" % ((i*PAYLOAD_SIZE)/duration/1000,
               100*float(PACKETS_NO-i)/PACKETS_NO))

    def test(self):
        """
        Bandwidth test method. Obtains a path to (2, 26) and sends PACKETS_NO
        packets (each with PAYLOAD_SIZE long payload) to a host in (2, 26).
        """
        addr = IPv4HostAddr("127.1.19.254")
        topo_file = "../topology/ISD1/topologies/ISD:1-AD:19-V:0.json"
        sender = SCIONDaemon.start(addr, topo_file)

        print("Sending PATH request for (2, 26) in 3 seconds.")
        time.sleep(3)
        paths = sender.get_paths(2, 26)
        self.assertTrue(paths)

        print("Starting the receiver.")
        threading.Thread(target=self.receiver).start()

        payload = b"A" * PAYLOAD_SIZE
        dst = IPv4HostAddr("127.2.26.254")
        spkt = SCIONPacket.from_values(sender.addr, dst, payload, paths[0])
        (next_hop, port) = sender.get_first_hop(spkt)
        print("Sending %d payload bytes (%d packets x %d bytes )\n" %
              (PACKETS_NO * PAYLOAD_SIZE, PACKETS_NO, PAYLOAD_SIZE))
        for _ in range(PACKETS_NO):
            sender.send(spkt, next_hop, port)
            time.sleep(SLEEP)
        print("Sending finished")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
