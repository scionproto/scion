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
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools
from external import ipaddress

# SCION
from lib.errors import SCIONParseError
from lib.packet.host_addr import (
    HostAddrBase,
    HostAddrIPv4,
    HostAddrIPv6,
    HostAddrSVC,
    haddr_parse_interface,
)
from lib.types import AddrType
from test.testcommon import assert_these_calls


# To allow testing of HostAddrBase, despite it having abstract methods.
class HostAddrBaseTesting(HostAddrBase):
    def _parse(self, raw):
        pass

    def pack(self):
        pass


class TestHostAddrIPv4Parse(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrIPv4._parse
    """
    @patch("lib.packet.host_addr.IPv4Interface", autospec=True)
    @patch("lib.packet.host_addr.HostAddrIPv4.__init__", autospec=True,
           return_value=None)
    def test(self, init, ipv4):
        inst = HostAddrIPv4("")
        # Call
        inst._parse("raw")
        # Tests
        ipv4.assert_called_once_with("raw")
        ntools.eq_(inst.addr, ipv4.return_value.ip)

    @patch("lib.packet.host_addr.IPv4Interface", autospec=True)
    @patch("lib.packet.host_addr.HostAddrIPv4.__init__", autospec=True,
           return_value=None)
    def test_wrong_len(self, init, ipv4):
        inst = HostAddrIPv4("")
        ipv4.side_effect = ipaddress.AddressValueError
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse, "raw")


class TestHostAddrIPv6Parse(object):
    """
    Unit tests for lib.packet.host_addr.HostAddrIPv6._parse
    """
    @patch("lib.packet.host_addr.IPv6Interface", autospec=True)
    @patch("lib.packet.host_addr.HostAddrIPv6.__init__", autospec=True,
           return_value=None)
    def test(self, init, ipv6):
        inst = HostAddrIPv6("")
        # Call
        inst._parse("raw")
        # Tests
        ipv6.assert_called_once_with("raw")
        ntools.eq_(inst.addr, ipv6.return_value.ip)

    @patch("lib.packet.host_addr.IPv6Interface", autospec=True)
    @patch("lib.packet.host_addr.HostAddrIPv6.__init__", autospec=True,
           return_value=None)
    def test_wrong_len(self, init, ipv6):
        inst = HostAddrIPv6("")
        ipv6.side_effect = ipaddress.AddressValueError
        # Call
        ntools.assert_raises(SCIONParseError, inst._parse, "raw")


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


class TestHaddrParseInterface(object):
    """
    Unit tests for lib.packet.host_addr.haddr_parse_interface
    """
    @patch("lib.packet.host_addr.haddr_parse", autospec=True)
    def test_v6(self, parse):
        ntools.eq_(haddr_parse_interface("v6 addr"), parse.return_value)
        # Tests
        parse.assert_called_once_with(AddrType.IPV6, "v6 addr")

    @patch("lib.packet.host_addr.haddr_parse", autospec=True)
    def test_v4(self, parse):
        parse.side_effect = iter([SCIONParseError, "v4 parsed"])
        # Call
        ntools.eq_(haddr_parse_interface("v4 addr"), "v4 parsed")
        # Tests
        assert_these_calls(parse, [
            call(AddrType.IPV6, "v4 addr"),
            call(AddrType.IPV4, "v4 addr"),
        ])

    @patch("lib.packet.host_addr.haddr_parse", autospec=True)
    def test_unknown(self, parse):
        parse.side_effect = iter([SCIONParseError, SCIONParseError])
        # Call
        ntools.assert_raises(SCIONParseError, haddr_parse_interface, "unknown")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
