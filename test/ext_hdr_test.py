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
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.ext_hdr import (
    ExtensionHeader,
    ICNExtHdr,
)


class TestExtensionHeaderInit(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.__init__
    """
    def test_basic(self):
        ext_hdr = ExtensionHeader()
        ntools.eq_(ext_hdr.next_ext, 0)
        ntools.eq_(ext_hdr.hdr_len, 0)
        ntools.assert_false(ext_hdr.parsed)

    @patch("lib.packet.ext_hdr.ExtensionHeader.parse")
    def test_raw(self, parse):
        ext_hdr = ExtensionHeader("data")
        parse.assert_called_once_with("data")
        
class TestExtensionHeaderPack(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.pack
    """
    def test_basic(self):
        ext_hdr = ExtensionHeader()
        ntools.assert_true(len(ext_hdr.pack()) >= ext_hdr.MIN_LEN)

class TestExtensionHeaderParse(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.parse
    """
    def test_basic(self):
        ext_hdr = ExtensionHeader()
        ext_hdr_copy = ExtensionHeader()
        ext_hdr_copy.parse(ext_hdr.pack())
        ntools.assert_true(ext_hdr.next_ext == ext_hdr_copy.next_ext)
        ntools.assert_true(ext_hdr.hdr_len == ext_hdr_copy.hdr_len)

    def test_len(self):
        ext_hdr = ExtensionHeader()
        ext_hdr.parse(bytes.fromhex('f0'))
        ntools.assert_false(ext_hdr.parsed)

class TestICNExtHdrInit(object):
    """
    Unit tests for lib.packet.ext_hdr.ICNExtHdr.__init__
    """
    def test_basic(self):
        iext_hdr = ICNExtHdr()
        ntools.eq_(iext_hdr.next_ext, 0)
        ntools.eq_(iext_hdr.hdr_len, 0)
        ntools.eq_(iext_hdr.fwd_flag, 0)
        ntools.assert_false(iext_hdr.parsed)

    @patch("lib.packet.ext_hdr.ICNExtHdr.parse")
    def test_raw(self, parse):
        iext_hdr = ICNExtHdr("data")
        parse.assert_called_once_with("data")

class TestICNExtHdrPack(object):
    """
    Unit tests for lib.packet.ext_hdr.ICNExtHdr.pack
    """
    def test_basic(self):
        iext_hdr = ICNExtHdr()
        ntools.assert_true(len(iext_hdr.pack()) >= iext_hdr.MIN_LEN)

class TestICNExtHdrParse(object):
    """
    Unit tests for lib.packet.ext_hdr.ICNExtHdr.parse
    """
    def test_basic(self):
        iext_hdr = ICNExtHdr()
        iext_hdr_copy = ICNExtHdr()
        iext_hdr_copy.parse(iext_hdr.pack())
        ntools.assert_true(iext_hdr.next_ext == iext_hdr_copy.next_ext)
        ntools.assert_true(iext_hdr.hdr_len == iext_hdr_copy.hdr_len)
        ntools.assert_true(iext_hdr.fwd_flag == iext_hdr_copy.fwd_flag)

    def test_len(self):
        iext_hdr = ICNExtHdr()
        iext_hdr.parse(bytes.fromhex('f0 f1 f0 f1 f0 f1 f0'))
        ntools.assert_false(iext_hdr.parsed)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
