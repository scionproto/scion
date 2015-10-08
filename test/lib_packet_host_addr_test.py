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
:mod:`lib_packet_host_addr_test` --- lib.packet.host_addr unit tests
====================================================================
"""
# Stdlib
import ipaddress
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.host_addr import (
    HostAddrInvalidType,
    HostAddrBase,
    HostAddrNone,
    HostAddrIPv4,
    HostAddrIPv6,
    HostAddrSVC,
    haddr_get_type,
    haddr_parse,
)
from test.testcommon import create_mock


# To allow testing of HostAddrBase, despite it having abstract methods.
class HostAddrBaseTesting(HostAddrBase):
    def _parse(self, raw):
        pass

    def pack(self):
        pass


class TestHostAddrBaseInit(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrBase.__init__
    """
    @patch.object(HostAddrBaseTesting, "_parse", autospec=True)
    def test_raw(self, parse):
        # Call
        inst = HostAddrBaseTesting("raw")
        # Tests
        ntools.assert_is_none(inst.addr)
        parse.assert_called_once_with(inst, "raw")

    def test_not_raw(self):
        # Call
        inst = HostAddrBaseTesting("addr", raw=False)
        # Tests
        ntools.eq_(inst.addr, "addr")


class TestHostAddrBaseStr(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrBase.__str__
    """
    @patch("lib.packet.host_addr.HostAddrBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = HostAddrBaseTesting("")
        inst.addr = create_mock(["__str__"])
        inst.addr.__str__.return_value = "str(addr)"
        # Call
        ntools.eq_(str(inst), "str(addr)")
        # Tests
        inst.addr.__str__.assert_called_once_with()


class TestHostAddrBaseLen(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrBase.__len__
    """
    @patch("lib.packet.host_addr.HostAddrBase.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = HostAddrBaseTesting("")
        inst.LEN = 42
        # Call
        ntools.eq_(len(inst), 42)


class TestHostAddrBaseEq(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrBase.__eq__
    """
    @patch("lib.packet.host_addr.HostAddrBase.__init__", autospec=True,
           return_value=None)
    def test_eq(self, init):
        inst = HostAddrBaseTesting("")
        other = create_mock(["TYPE", "addr"])
        inst.TYPE = other.TYPE = 42
        inst.addr = other.addr = "addr"
        # Call
        ntools.assert_true(inst == other)

    @patch("lib.packet.host_addr.HostAddrBase.__init__", autospec=True,
           return_value=None)
    def test_neq_type(self, init):
        inst = HostAddrBaseTesting("")
        other = create_mock(["TYPE", "addr"])
        inst.TYPE = 41
        other.TYPE = 42
        inst.addr = other.addr = "addr"
        # Call
        ntools.assert_false(inst == other)

    @patch("lib.packet.host_addr.HostAddrBase.__init__", autospec=True,
           return_value=None)
    def test_neq_addr(self, init):
        inst = HostAddrBaseTesting("")
        other = create_mock(["TYPE", "addr"])
        inst.TYPE = other.TYPE = 42
        inst.addr = "addr0"
        other.addr = "addr1"
        # Call
        ntools.assert_false(inst == other)


class TestHostAddrNoneInit(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrNone.__init__
    """
    def test(self):
        # Call
        inst = HostAddrNone()
        # Tests
        ntools.assert_is_none(inst.addr)


class TestHostAddrNonePack(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrNone.pack
    """
    def test(self):
        # Call
        inst = HostAddrNone()
        # Tests
        ntools.eq_(inst.pack(), b"")


class TestHostAddrIPv4Parse(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrIPv4._parse
    """
    @patch("lib.packet.host_addr.IPv4Address", autospec=True)
    @patch("lib.packet.host_addr.HostAddrIPv4.__init__", autospec=True,
           return_value=None)
    def test(self, init, ipv4):
        inst = HostAddrIPv4("")
        # Call
        inst._parse("raw")
        # Tests
        ipv4.assert_called_once_with("raw")
        ntools.eq_(inst.addr, ipv4.return_value)

    @patch("lib.packet.host_addr.IPv4Address", autospec=True)
    @patch("lib.packet.host_addr.HostAddrIPv4.__init__", autospec=True,
           return_value=None)
    def test_wrong_len(self, init, ipv4):
        inst = HostAddrIPv4("")
        ipv4.side_effect = ipaddress.AddressValueError
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse, "raw")


class TestHostAddrIPv4Pack(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrIPv4.pack
    """
    @patch("lib.packet.host_addr.HostAddrIPv4.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = HostAddrIPv4("")
        inst.addr = create_mock(["packed"])
        # Call
        ntools.eq_(inst.pack(), inst.addr.packed)


class TestHostAddrIPv6Parse(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrIPv6._parse
    """
    @patch("lib.packet.host_addr.IPv6Address", autospec=True)
    @patch("lib.packet.host_addr.HostAddrIPv6.__init__", autospec=True,
           return_value=None)
    def test(self, init, ipv6):
        inst = HostAddrIPv6("")
        # Call
        inst._parse("raw")
        # Tests
        ipv6.assert_called_once_with("raw")
        ntools.eq_(inst.addr, ipv6.return_value)

    @patch("lib.packet.host_addr.IPv6Address", autospec=True)
    @patch("lib.packet.host_addr.HostAddrIPv6.__init__", autospec=True,
           return_value=None)
    def test_wrong_len(self, init, ipv6):
        inst = HostAddrIPv6("")
        ipv6.side_effect = ipaddress.AddressValueError
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse, "raw")


class TestHostAddrIPv6Pack(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrIPv6.pack
    """
    @patch("lib.packet.host_addr.HostAddrIPv6.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = HostAddrIPv6("")
        inst.addr = create_mock(["packed"])
        # Call
        ntools.eq_(inst.pack(), inst.addr.packed)


class TestHostAddrSVCParse(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrSVC._parse
    """
    @patch("lib.packet.host_addr.Raw", autospec=True)
    @patch("lib.packet.host_addr.HostAddrSVC.__init__", autospec=True,
           return_value=None)
    def test(self, init, raw):
        inst = HostAddrSVC("")
        pop = raw.return_value.pop
        pop.return_value = bytes.fromhex("01 0f")
        # Call
        inst._parse("raw")
        # Tests
        raw.assert_called_once_with("raw", "HostAddrSVC", inst.LEN)
        ntools.eq_(inst.addr, 0x010f)


class TestHostAddrSVCPack(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrSVC.pack
    """
    @patch("lib.packet.host_addr.HostAddrSVC.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = HostAddrSVC("")
        inst.addr = 0x010f
        # Call
        ntools.eq_(inst.pack(), bytes.fromhex("01 0f"))


class TestHaddrGetType(object):
    """
    Unit tests for lib.packet.host_addr.haddr_get_type
    """
    def _check(self, type_, expected):
        ntools.eq_(haddr_get_type(type_), expected)

    def test(self):
        for type_, expected in (
            (0, HostAddrNone),
            ("NONE", HostAddrNone),
            (1, HostAddrIPv4),
            ("IPV4", HostAddrIPv4),
            (2, HostAddrIPv6),
            ("IPV6", HostAddrIPv6),
            (3, HostAddrSVC),
            ("SVC", HostAddrSVC),
        ):
            yield self._check, type_, expected

    def test_invalid(self):
        ntools.assert_raises(HostAddrInvalidType, haddr_get_type, "invalid")


class TestHaddrParse(object):
    """
    Unit tests for lib.packet.host_addr.haddr_parse
    """
    @patch("lib.packet.host_addr.haddr_get_type", autospec=True)
    def test(self, get_type):
        # Call
        ntools.eq_(haddr_parse("type", "args"),
                   get_type.return_value.return_value)
        # Tests
        get_type.assert_called_once_with("type")
        get_type.return_value.assert_called_once_with("args")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
