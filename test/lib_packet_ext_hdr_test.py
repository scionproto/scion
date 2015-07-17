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
        """

        """
        ext_hdr = ExtensionHeader()
        ntools.eq_(ext_hdr.next_hdr, 0)
        ntools.eq_(ext_hdr._hdr_len, 0)
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
        ext_hdr.next_hdr = 14
        ext_hdr._hdr_len = 42
        # Extensions are padded
        ntools.eq_(ext_hdr.pack(), bytes([14, 42, 00, 00, 00, 00, 00, 00]))


class TestExtensionHeaderParse(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.parse
    """

    def test_basic(self):
        """

        """
        ext_hdr = ExtensionHeader()
        ext_hdr.parse(bytes([14, 00, 00, 00, 00, 00, 00, 00]))
        ntools.eq_(ext_hdr.next_hdr, 14)
        ntools.eq_(ext_hdr._hdr_len, 00)
        ntools.assert_true(ext_hdr.parsed)

    def test_len(self):
        """

        """
        ext_hdr = ExtensionHeader()
        ext_hdr.parse(bytes([14]))
        ntools.assert_false(ext_hdr.parsed)
        ntools.eq_(ext_hdr.next_hdr, 0)
        ntools.eq_(ext_hdr._hdr_len, 0)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
