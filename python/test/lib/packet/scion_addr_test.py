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
from test.testcommon import assert_these_calls, create_mock, create_mock_full


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
    def _check_success(self, ia_s, isd, as_):
        inst = ISD_AS()
        # Call
        inst._parse_str(ia_s)
        # Tests
        ntools.eq_(inst._isd, isd)
        ntools.eq_(inst._as, as_)

    def test_success(self):
        for ia_s, isd, as_ in (
            ("0-0", 0, 0),
            ("1-1", 1, 1),
            ("65535-1", ISD_AS.MAX_ISD, 1),
            ("1-4294967295", 1, ISD_AS.MAX_BGP_AS),
            ("1-1:0:0", 1, 0x000100000000),
            ("1-1:fcd1:1", 1, 0x0001fcd10001),
            ("65535-ffff:ffff:ffff", ISD_AS.MAX_ISD, ISD_AS.MAX_AS),
        ):
            yield self._check_success, ia_s, isd, as_

    def _check_excp(self, isd_as):
        inst = ISD_AS()
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse_str, isd_as)

    def test_excp(self):
        for isd_as in (
            "",
            "a",
            "1a-2b",
            "-",
            "1-",
            "-1",
            "-1-",
            "65536-1",
            "1-4294967296",
            "1-1_0000",
            "1-ffff:ffff:10000"
        ):
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


class TestISDASIsdStr(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AS.isd_str
    """
    def _check(self, isd, s):
        inst = ISD_AS()
        inst._isd = isd
        # Call
        ntools.eq_(inst.isd_str(), s)

    def test(self):
        for isd, s in (
            (0, "0"),
            (1, "1"),
            (65535, "65535"),
            (65536, "65536 [Illegal ISD: larger than 65535]"),
        ):
            yield self._check, isd, s


class TestISDASAsStr(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AS.as_str
    """
    def _check(self, as_, s):
        inst = ISD_AS()
        inst._as = as_
        # Call
        ntools.eq_(inst.as_str(), s)

    def test(self):
        for as_, s in (
            (0, "0"),
            (1, "1"),
            (999, "999"),
            (ISD_AS.MAX_BGP_AS, "4294967295"),
            (ISD_AS.MAX_BGP_AS + 1, "1:0:0"),
            (0x0001fcd10001, "1:fcd1:1"),
            (ISD_AS.MAX_AS, "ffff:ffff:ffff"),
            (ISD_AS.MAX_AS + 1, "281474976710656 [Illegal AS: larger than 281474976710655]"),
        ):
            yield self._check, as_, s


class TestISDASStr(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AS.__str__
    """
    def test(self):
        inst = ISD_AS()
        inst.isd_str = create_mock_full()
        inst.as_str = create_mock_full()
        # Call
        ntools.eq_(str(inst), "%s-%s" % (inst.isd_str.return_value, inst.as_str.return_value))


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
