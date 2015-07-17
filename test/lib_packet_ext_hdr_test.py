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
from unittest.mock import patch

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
        ntools.eq_(ext_hdr.next_hdr, 0)
        ntools.eq_(ext_hdr._hdr_len, 0)
        ntools.eq_(ext_hdr.payload, b"\x00" * 6)
        ntools.assert_false(ext_hdr.parsed)

    @patch("lib.packet.ext_hdr.ExtensionHeader.parse", autospec=True)
    def test_raw(self, parse):
        ext_hdr = ExtensionHeader("data")
        parse.assert_called_once_with(ext_hdr, "data")


class TestExtensionHeaderParse(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.parse
    """
    def test_bad_type(self):
        ext_hdr = ExtensionHeader()
        ntools.assert_raises(AssertionError, ext_hdr.parse, 123)

    @patch("lib.packet.ext_hdr.logging.warning", autospec=True)
    def test_short_data(self, log_warning):
        ext_hdr = ExtensionHeader()
        dlen = ExtensionHeader.MIN_LEN - 1
        data = bytes(range(dlen))
        ext_hdr.parse(data)
        ntools.eq_(log_warning.call_count, 1)
        ntools.assert_false(ext_hdr.parsed)

    def test_bad_len(self):
        data = bytes.fromhex('01 02 03 04 05 06 07 08')
        ext_hdr = ExtensionHeader()
        ntools.assert_raises(AssertionError, ext_hdr.parse, data)
        ntools.eq_(ext_hdr.next_hdr, 0x01)
        ntools.eq_(ext_hdr._hdr_len, 0x02)

    @patch("lib.packet.ext_hdr.ExtensionHeader.__len__", autospec=True)
    @patch("lib.packet.ext_hdr.ExtensionHeader.set_payload", autospec=True)
    def test_full(self, set_payload, ext_hdr_len):
        ext_hdr_len.return_value = 8
        ext_hdr = ExtensionHeader()
        ext_hdr.parse(bytes.fromhex('01 02 03 04 05 06 07 08'))
        ntools.eq_(ext_hdr.next_hdr, 0x01)
        ntools.eq_(ext_hdr._hdr_len, 0x02)
        set_payload.assert_called_once_with(ext_hdr, bytes.fromhex('03 04 05 '
                                                                   '06 07 08'))
        ntools.assert_true(ext_hdr.parsed)


class TestExtensionHeaderSetPayload(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.set_payload
    """
    def test_short_payload(self):
        payload = bytes.fromhex('01 02 03')
        ext_hdr = ExtensionHeader()
        ext_hdr.set_payload(payload)
        ntools.eq_(ext_hdr._hdr_len, 0)
        ntools.eq_(ext_hdr.payload, bytes.fromhex('01 02 03 00 00 00'))

    def test_not_multiple(self):
        payload = bytes(range(9))
        ext_hdr = ExtensionHeader()
        ext_hdr.set_payload(payload)
        ntools.eq_(ext_hdr._hdr_len, 1)
        ntools.eq_(ext_hdr.payload, payload + b"\x00" * 5)

    def test_multiple(self):
        payload = bytes(range(6 + 8))
        ext_hdr = ExtensionHeader()
        ext_hdr.set_payload(payload)
        ntools.eq_(ext_hdr._hdr_len, 1)
        ntools.eq_(ext_hdr.payload, payload)


class TestExtensionHeaderPack(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.pack
    """
    def test_basic(self):
        ext_hdr = ExtensionHeader()
        ext_hdr.next_hdr = 14
        ext_hdr._hdr_len = 42
        ext_hdr.payload = bytes.fromhex('01 02 03')
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
