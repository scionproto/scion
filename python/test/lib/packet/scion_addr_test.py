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
:mod:`lib_packet_scion_addr_test` --- lib.packet.scion_addr unit tests
======================================================================
"""
# Stdlib
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.scion_addr import SCIONAddr, ISD_AS
from test.testcommon import assert_these_calls, create_mock


class TestISDASParseBytes(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AS._parse_bytes
    """
    @patch("lib.packet.scion_addr.Raw", autospec=True)
    def test(self, raw):
        inst = ISD_AS()
        data = create_mock(["pop"])
        data.pop.return_value = bytes.fromhex("F011F23344556677")
        raw.return_value = data
        # Call
        inst._parse_bytes("data")
        # Tests
        raw.assert_called_once_with("data", ISD_AS.NAME, ISD_AS.LEN)
        ntools.eq_(inst._isd, 0xF011)
        ntools.eq_(inst._as, 0xF23344556677)


class TestISDASParseStr(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AS._parse_str
    """
    def test_success(self):
        inst = ISD_AS()
        # Call
        inst._parse_str("4095-99")
        # Tests
        ntools.eq_(inst._isd, 4095)
        ntools.eq_(inst._as, 99)

    def _check_excp(self, isd_as):
        inst = ISD_AS()
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse_str, isd_as)

    def test_excp(self):
        for isd_as in ("0-nope", "argh-99"):
            yield self._check_excp, isd_as


class TestISDASParseInt(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AS._parse_int
    """
    def test(self):
        inst = ISD_AS()
        # Call
        inst._parse_int(0xF011F23344556677)
        # Tests
        ntools.eq_(inst._isd, 0xF011)
        ntools.eq_(inst._as, 0xF23344556677)


class TestISDASPack(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AS.pack
    """
    def test(self):
        inst = ISD_AS()
        inst._isd = 0xF011
        inst._as = 0xF23344556677
        # Call
        ntools.eq_(inst.pack(), bytes.fromhex("F011F23344556677"))


class TestSCIONAddrParse(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr._parse
    """

    @patch("lib.packet.scion_addr.ISD_AS", autospec=True)
    @patch("lib.packet.scion_addr.Raw", autospec=True)
    @patch("lib.packet.scion_addr.haddr_get_type", autospec=True)
    def test(self, get_type, raw, isd_as):
        # Setup
        inst = SCIONAddr()
        haddr_type = create_mock(["LEN"])
        haddr_type.LEN = 42
        get_type.return_value = haddr_type
        data = create_mock(["pop"])
        data.pop.side_effect = ("isd-as", "raw addr")
        raw.return_value = data
        isd_as.LEN = 4
        # Call
        inst._parse("atype", "data")
        # Tests
        get_type.assert_called_once_with("atype")
        raw.assert_called_once_with(
            "data", "SCIONAddr", 42 + 4, min_=True)
        assert_these_calls(data.pop, [call(4), call(42)])
        isd_as.assert_called_once_with("isd-as")
        ntools.eq_(inst.isd_as, isd_as.return_value)
        haddr_type.assert_called_once_with("raw addr")
        ntools.eq_(inst.host, haddr_type.return_value)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
