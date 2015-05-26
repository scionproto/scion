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
        eh = ExtensionHeader()
        self.assertFalse(eh.parsed)
        ehCopy = ExtensionHeader()
        ehCopy.parse(eh.pack());
        self.assertTrue(eh.next_ext == ehCopy.next_ext and
                        eh.hdr_len == ehCopy.hdr_len and
                        ehCopy.parsed)
    def test_equality(self):
        """
        Make sure that equality tests between extension headers succeeds for
        the same type of extension headers.
        """
        eh1 = ExtensionHeader()
        eh2 = ExtensionHeader()
        ieh1 = ICNExtHdr()
        ieh2 = ICNExtHdr()
        self.assertTrue(eh1.next_ext == eh2.next_ext and
                        eh1.hdr_len == eh2.hdr_len)
        self.assertTrue(ieh1.next_ext == ieh2.next_ext and
                        ieh1.hdr_len == ieh2.hdr_len and
                        ieh1.fwd_flag == ieh2.fwd_flag)
    def test_icn_extension_header(self):
        """
        Ensure that parsing a packed icn extension header results in same icn extension
        header
        """
        ieh = ICNExtHdr()
        iehCopy = ICNExtHdr()
        iehCopy.parse(ieh.pack());
        self.assertTrue(ieh.next_ext == iehCopy.next_ext and
                        ieh.hdr_len == iehCopy.hdr_len and
                        ieh.fwd_flag == iehCopy.fwd_flag and
                        iehCopy.parsed)
if __name__ == "__main__":
    unittest.main()
