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
:mod:`lib_packet_ext_hdr_test` --- lib.packet.ext_hdr unit tests
================================================================
"""
# Stdlib
from unittest.mock import MagicMock, patch

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
        """

        """
        ext_hdr = ExtensionHeader()
        ntools.eq_(ext_hdr.next_ext, 0)
        ntools.eq_(ext_hdr.hdr_len, 0)
        ntools.assert_false(ext_hdr.parsed)

    @patch("lib.packet.ext_hdr.ExtensionHeader.parse", autospec=True)
    def test_raw(self, parse):
        """

        """
        ext_hdr = ExtensionHeader("data")
        parse.assert_called_once_with(ext_hdr, "data")


class TestExtensionHeaderPack(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.pack
    """

    def test_basic(self):
        """

        """
        ext_hdr = ExtensionHeader()
        ext_hdr.next_ext = 14
        ext_hdr.hdr_len = 42
        ntools.eq_(ext_hdr.pack(), bytes([14, 42]))


class TestExtensionHeaderParse(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.parse
    """

    @patch("lib.packet.ext_hdr.Raw", autospec=True)
    def test_basic(self, raw):
        """

        """
        # Setup
        ext_hdr = ExtensionHeader()
        data = bytes([14, 42])
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.return_value = data
        # Call
        ext_hdr.parse(data)
        # Tests
        raw.assert_called_once_with(data, "ExtensionHeader", ext_hdr.MIN_LEN)
        ntools.eq_(ext_hdr.next_ext, 14)
        ntools.eq_(ext_hdr.hdr_len, 42)
        ntools.assert_true(ext_hdr.parsed)


class TestICNExtHdrInit(object):
    """
    Unit tests for lib.packet.ext_hdr.ICNExtHdr.__init__
    """

    def test_basic(self):
        """

        """
        iext_hdr = ICNExtHdr()
        ntools.eq_(iext_hdr.next_ext, 0)
        ntools.eq_(iext_hdr.hdr_len, 0)
        ntools.eq_(iext_hdr.fwd_flag, 0)
        ntools.assert_false(iext_hdr.parsed)

    @patch("lib.packet.ext_hdr.ICNExtHdr.parse", autospec=True)
    def test_raw(self, parse):
        """

        """
        iext_hdr = ICNExtHdr("data")
        parse.assert_called_once_with(iext_hdr, "data")


class TestICNExtHdrParse(object):
    """
    Unit tests for lib.packet.ext_hdr.ICNExtHdr.parse
    """
    @patch("lib.packet.ext_hdr.Raw", autospec=True)
    def test_basic(self, raw):
        """

        """
        # Setup
        iext_hdr = ICNExtHdr()
        data = bytes([14, 42, 10, 0, 0, 0, 0, 0])
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.return_value = data
        # Call
        iext_hdr.parse(data)
        # Tests
        raw.assert_called_once_with(data, "ICNExtHdr",
                                    iext_hdr.MIN_LEN, min_=True)
        ntools.eq_(iext_hdr.next_ext, 14)
        ntools.eq_(iext_hdr.hdr_len, 42)
        ntools.eq_(iext_hdr.fwd_flag, 10)
        ntools.assert_true(iext_hdr.parsed)


class TestICNExtHdrPack(object):
    """
    Unit tests for lib.packet.ext_hdr.ICNExtHdr.pack
    """

    def test_basic(self):
        """

        """
        iext_hdr = ICNExtHdr()
        iext_hdr.next_ext = 14
        iext_hdr.hdr_len = 42
        iext_hdr.fwd_flag = 10
        ntools.eq_(iext_hdr.pack(), bytes([14, 42, 10, 0, 0, 0, 0, 0]))


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
