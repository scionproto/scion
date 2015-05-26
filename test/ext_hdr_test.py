# Copyright 2015 ETH Zurich
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
:mod:`ext_hdr_test` --- SCION extension header tests
=====================================================
"""
# Stdlib
import unittest

# SCION
from lib.packet.ext_hdr import (
    ExtensionHeader,
    ICNExtHdr,
)
from test.testcommon import SCIONCommonTest


class TestExtensionHeaders(SCIONCommonTest):
    """
    Unit tests for ext_hdr.py.
    """
    def test_extension_header(self):
        """
        Ensure that parsing a packed extension header results in same extension
        header
        """
        ext_hdr = ExtensionHeader()
        self.assertFalse(ext_hdr.parsed)
        ext_hdr_copy = ExtensionHeader()
        ext_hdr_copy.parse(ext_hdr.pack())
        self.assertTrue(ext_hdr.next_ext == ext_hdr_copy.next_ext and
                        ext_hdr.hdr_len == ext_hdr_copy.hdr_len and
                        ext_hdr_copy.parsed)
    def test_equality(self):
        """
        Ensures that equality tests between extension headers succeeds for
        the same type of extension headers.
        """
        ext_hdr1 = ExtensionHeader()
        ext_hdr2 = ExtensionHeader()
        iext_hdr1 = ICNExtHdr()
        iext_hdr2 = ICNExtHdr()
        self.assertTrue(ext_hdr1.next_ext == ext_hdr2.next_ext and
                        ext_hdr1.hdr_len == ext_hdr2.hdr_len)
        self.assertTrue(iext_hdr1.next_ext == iext_hdr2.next_ext and
                        iext_hdr1.hdr_len == iext_hdr2.hdr_len and
                        iext_hdr1.fwd_flag == iext_hdr2.fwd_flag)
    def test_icn_extension_header(self):
        """
        Ensure that parsing a packed icn extension header results in same icn
        extension header
        """
        iext_hdr = ICNExtHdr()
        iext_hdr_copy = ICNExtHdr()
        iext_hdr_copy.parse(iext_hdr.pack())
        self.assertTrue(iext_hdr.next_ext == iext_hdr_copy.next_ext and
                        iext_hdr.hdr_len == iext_hdr_copy.hdr_len and
                        iext_hdr.fwd_flag == iext_hdr_copy.fwd_flag and
                        iext_hdr_copy.parsed)
if __name__ == "__main__":
    unittest.main()
