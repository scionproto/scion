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
from lib.packet.scion import PathInfo, PathInfoType, SCIONPacket
import logging
import sys
import threading
import time
import unittest

from endhost.sciond import SCIONDaemon


class TestSCIONDaemon(unittest.TestCase):
    """
    Unit tests for sciond.py. For this test a infrastructure must be running.
    """

    def test(self):
        """
        Testing function. Creates an instance of SCIONDaemon, then verifies path
        requesting, and finally sends packet through SCION. Sender is
        192.168.7.107 placed in ISD:1, AD:19, and receiver is 192.168.6.106 in
        ISD:2, AD:26.
        """

        addr = IPv4HostAddr("127.0.0.1")
        topo_file = "../topology/ISD1/topologies/ISD:1-AD:19-V:0.json"
        sd = SCIONDaemon.start(addr, topo_file)

        print("Sending PATH request for (2, 26) in 5 seconds")
        time.sleep(5)
        paths = sd.get_paths(2, 26)
        self.assertTrue(paths)

#         dst = IPv4HostAddr("192.168.6.106")
#         spkt = SCIONPacket.from_values(sd.addr, dst, b"payload", path)
#         (next_hop, port) = sd.get_first_hop(spkt)
#         print("Sending packet: %s\nFirst hop: %s:%s" % (spkt, next_hop, port))
#         sd.send(spkt, next_hop, port)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
