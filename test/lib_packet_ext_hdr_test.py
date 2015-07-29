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
)


class TestExtensionHeaderInit(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.__init__
    """
    def test_basic(self):
        ext_hdr = ExtensionHeader()
        ext_hdr.EXT_NO = 0
        ntools.eq_(ext_hdr.next_hdr, 0)
        ntools.eq_(ext_hdr._hdr_len, 0)
        ntools.eq_(ext_hdr.payload, b"\x00" * 5)
        ntools.assert_false(ext_hdr.parsed)

    @patch("lib.packet.ext_hdr.ExtensionHeader.parse", autospec=True)
    def test_raw(self, parse):
        ext_hdr = ExtensionHeader("data")
        parse.assert_called_once_with(ext_hdr, "data")


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


class TestExtensionHeaderSetPayload(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.set_payload
    """
    def test_short_payload(self):
        payload = bytes.fromhex('01 02 03 04 05')
        ext_hdr = ExtensionHeader()
        ext_hdr.set_payload(payload)
        ntools.eq_(ext_hdr._hdr_len, 0)
        ntools.eq_(ext_hdr.payload, bytes.fromhex('01 02 03 04 05'))

    def test_not_multiple(self):
        payload = bytes(range(13))
        ext_hdr = ExtensionHeader()
        ext_hdr._init_size(1)
        ext_hdr.set_payload(payload)
        ntools.eq_(ext_hdr._hdr_len, 1)
        ntools.eq_(ext_hdr.payload, payload)

    def test_multiple(self):
        payload = bytes(range(5 + 2*8))
        ext_hdr = ExtensionHeader()
        ext_hdr._init_size(2)
        ext_hdr.set_payload(payload)
        ntools.eq_(ext_hdr._hdr_len, 2)
        ntools.eq_(ext_hdr.payload, payload)


class TestExtensionHeaderPack(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.pack
    """
    def test_basic(self):
        ext_hdr = ExtensionHeader()
        ext_hdr.next_hdr = 14
        ext_hdr._hdr_len = 42
        ext_hdr.EXT_NO = 1
        ext_hdr.payload = bytes.fromhex('02 03')
        ntools.eq_(ext_hdr.pack(), bytes([14, 42, 1, 2, 3]))


class TestExtensionHeaderLen(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.__len__
    """
    def test(self):
        ext_hdr = ExtensionHeader()
        ext_hdr._hdr_len = 123
        ntools.eq_(len(ext_hdr), 124 * ExtensionHeader.MIN_LEN)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
