"""
opaque_field_test.py

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
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.scion import SCIONPacket
import logging
import time
import unittest
import sys

from endhost.sciond import SCIONDaemon

ping_received = False
pong_received = False

class PingPongEndhost(SCIONDaemon):

    def handle_data_packet(self, spkt):
        """
        Handles SCION data packet.
        """
        global ping_received
        global pong_received

        if spkt.payload == b"ping":
            # Reverse the packet and send "pong".
            print('%s: ping received, sending pong.' % self.addr)
            ping_received = True
            spkt.hdr.reverse()
            spkt.payload = b"pong"
            (next_hop, port) = self.get_first_hop(spkt)
            self.send(spkt, next_hop, port)
        elif spkt.payload == b"pong":
            print('%s: pong received.' % self.addr)
            pong_received = True
        else:
            print("Wrong payload.")


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

        saddr = IPv4HostAddr("127.1.19.1")
        topo_file = "../topology/ISD1/topologies/ISD:1-AD:19-V:0.xml"
        sender = PingPongEndhost.start(saddr, topo_file)

        raddr = IPv4HostAddr("127.2.26.1")
        topo_file = "../topology/ISD2/topologies/ISD:2-AD:26-V:0.xml"
        receiver = PingPongEndhost.start(raddr, topo_file)

        print("Sending PATH request for (2, 26) in 3 seconds")
        time.sleep(3)
        paths = sender.get_paths(2, 26)
        self.assertTrue(paths)

        spkt = SCIONPacket.from_values(sender.addr, raddr, b"ping", paths[0])
        (next_hop, port) = sender.get_first_hop(spkt)
        print("Sending packet: %s\nFirst hop: %s:%s\n" % (spkt, next_hop, port))
        sender.send(spkt, next_hop, port)

        time.sleep(1)
        self.assertTrue(ping_received)
        self.assertTrue(pong_received)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
