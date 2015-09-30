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
from test.testcommon import create_mock


# To allow testing of ExtensionHeader, despite it having abstract methods.
class ExtensionHeaderTesting(ExtensionHeader):
    def from_values(cls):
        raise NotImplementedError

    def pack(self):
        raise NotImplementedError


class TestExtensionHeaderInit(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.__init__
    """
    @patch("lib.packet.scion.ExtensionHeader._parse", autospec=True)
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True)
    def test_basic(self, super_init, parse):
        inst = ExtensionHeaderTesting()
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.eq_(inst._hdr_len, 0)
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion.ExtensionHeader._parse", autospec=True)
    @patch("lib.packet.scion.HeaderBase.__init__", autospec=True)
    def test_raw(self, super_init, parse):
        inst = ExtensionHeaderTesting("data")
        # Tests
        parse.assert_called_once_with(inst, "data")


class TestExtensionHeaderParse(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader._parse
    """
    @patch("lib.packet.ext_hdr.Raw", autospec=True)
    def test_basic(self, raw):
        inst = ExtensionHeaderTesting()
        inst._set_payload = create_mock()
        data = create_mock(["__len__", "pop"])
        data.__len__.return_value = 5
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "ExtensionHeader", inst.MIN_LEN,
                                    min_=True)
        inst._set_payload.assert_called_once_with(data.pop.return_value)


class TestExtensionHeaderInitSize(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader._init_size
    """
    def test(self):
        inst = ExtensionHeaderTesting()
        inst._set_payload = create_mock()
        # Call
        inst._init_size(10)
        # Tests
        ntools.eq_(inst._hdr_len, 10)
        inst._set_payload.assert_called_once_with(bytes(85))


class TestExtensionHeaderSetPayload(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader._set_payload
    """
    def test_shortest_payload(self):
        payload = bytes(5)
        inst = ExtensionHeaderTesting()
        # Call
        inst._set_payload(payload)
        # Tests
        ntools.eq_(inst._raw, payload)

    def test_short_payload(self):
        payload = bytes(5 + 8)
        inst = ExtensionHeaderTesting()
        inst._hdr_len = 1
        # Call
        inst._set_payload(payload)
        # Tests
        ntools.eq_(inst._raw, payload)

    def test_longer_payload(self):
        payload = bytes(5 + 2*8)
        inst = ExtensionHeaderTesting()
        inst._hdr_len = 2
        # Call
        inst._set_payload(payload)
        # Tests
        ntools.eq_(inst._raw, payload)


class TestExtensionHeaderLen(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.__len__
    """
    def test(self):
        inst = ExtensionHeaderTesting()
        inst.hdr_len_to_bytes = create_mock()
        inst.hdr_len_to_bytes.return_value = 3
        ntools.eq_(len(inst), 3)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
