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
from lib.packet.scion import SCIONCommonHdr, PacketType
import unittest


class TestCommonHeader(unittest.TestCase):
    """
    Unit tests for scion.py.
    """

    def test_opaque_field(self):
        sch = SCIONCommonHdr()
        self.assertTrue(sch.type == PacketType.DATA)

    def test_equality(self):
        sch1 = SCIONCommonHdr()
        sch2 = SCIONCommonHdr()
        self.assertTrue(sch1.type == sch2.type)

    def test_pack_and_parse(self):
        sch = SCIONCommonHdr.from_values(PacketType.DATA, 4, 4, 0)

        schCopy = SCIONCommonHdr()
        schCopy.parse(sch.pack())
        self.assertTrue(sch.type == schCopy.type)
        self.assertTrue(sch.src_addr_len == schCopy.src_addr_len)
        self.assertTrue(sch.dst_addr_len == schCopy.dst_addr_len)
        self.assertTrue(sch.total_len == schCopy.total_len)
        self.assertTrue(sch.curr_iof_p == schCopy.curr_iof_p)
        self.assertTrue(sch.curr_of_p == schCopy.curr_of_p)
        self.assertTrue(sch.next_hdr == schCopy.next_hdr)
        self.assertTrue(sch.hdr_len == schCopy.hdr_len)


if __name__ == "__main__":
    unittest.main()
