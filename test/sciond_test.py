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
from endhost.sciond import SCIONDaemon
from lib.packet.host_addr import IPv4HostAddr
from lib.packet.scion import PathInfo, PathInfoType, SCIONPacket
import sys
import threading
import time
import unittest
import logging

class TestSCIONDaemon(unittest.TestCase):
    """
    Unit tests for sciond.py. For this test a infrastructure must be running.
    """

    def test(self):
        """
        Testing function. Creates instance of SCIONDaemon, verifies path
        requesting, and finally sends packet through SCION. Sender is
        192.168.7.107 placed in ISD:11, AD:7, and receiver is 192.168.6.106 in
        ISD:11, AD:6.
        """
        addr = IPv4HostAddr("192.168.7.107")
        conf_file = "../topology/ISD11/topologies/topology7.xml"
        sd = SCIONDaemon(addr, conf_file)
        threading.Thread(target=sd.run).start()

        print("Sending UP_PATH request in 5 seconds")
        time.sleep(5)
        sd.request_paths(PathInfoType.UP, 0, 0)
        print("Sending DOWN_PATH request in 3 seconds")
        time.sleep(3)
        self.assertTrue(sd.up_paths)
        sd.request_paths(PathInfoType.DOWN, 11, 5)
        print("Clearing cache and sending BOTH_PATHS request in 3 seconds")
        time.sleep(3)
        self.assertTrue(sd.down_paths)

        sd.up_paths = []
        sd.down_paths = {}
        sd._waiting_targets = {}

        time.sleep(3)

        print("Requesting path for (11, 6)")
        paths = sd.get_paths(11, 6)
        self.assertTrue(paths)
        path = paths[0]

        dst = IPv4HostAddr("192.168.6.106")
        spkt = SCIONPacket.from_values(sd.addr, dst, b"payload", path)
        (next_hop, port) = sd.get_first_hop(spkt)
        print("Sending packet: %s\nFirst hop: %s:%s" % (spkt, next_hop, port))
        sd.send(spkt, next_hop, port)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    unittest.main()
