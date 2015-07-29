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
from ipaddress import IPv4Address, IPv6Address
from unittest.mock import MagicMock, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.scion_addr import SCIONAddr, ISD_AD


class TestSCIONAddrInit(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.__init__
    """

    def test_basic(self):
        """
        Test basic functionality.
        """
        addr = SCIONAddr()
        ntools.eq_(addr.isd_id, None)
        ntools.eq_(addr.ad_id, None)
        ntools.eq_(addr.host_addr, None)
        ntools.eq_(addr.addr_len, 0)

    @patch("lib.packet.scion_addr.SCIONAddr.parse")
    def test_raw(self, parse):
        """
        Test from raw input.
        """
        SCIONAddr("data")
        parse.assert_called_once_with("data")


class TestSCIONAddrFromValues(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.from_values
    """

    def test(self):
        # Setup
        isd_id = 1
        ad_id = 10
        host_addr = MagicMock(spec_set=["packed"])
        host_addr.packed = "123"
        # Call
        addr = SCIONAddr.from_values(isd_id, ad_id, host_addr)
        # Tests
        ntools.assert_is_instance(addr, SCIONAddr)
        ntools.eq_(addr.isd_id, isd_id)
        ntools.eq_(addr.ad_id, ad_id)
        ntools.eq_(addr.host_addr, host_addr)
        ntools.eq_(addr.addr_len, ISD_AD.LEN + 3)


class TestSCIONAddrParse(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.parse
    """

    @patch("lib.packet.scion_addr.ISD_AD.from_raw", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.scion_addr.Raw", autospec=True)
    def _check(self, ip, raw, isdad_raw):
        # Setup
        data = b"sadr" + ip.packed
        raw.return_value = MagicMock(spec_set=["__len__", "pop"])
        raw.return_value.__len__.side_effect = [len(data), len(ip.packed)]
        raw.return_value.pop.side_effect = ("pop isd_ad", ip.packed)
        isdad_raw.return_value = (1, 10)
        addr = SCIONAddr()
        # Call
        addr.parse(data)
        # Tests
        raw.assert_called_once_with(data, "SCIONAddr", 8, min_=True)
        isdad_raw.assert_called_once_with("pop isd_ad")
        ntools.eq_(addr.addr_len, len(data))
        ntools.eq_(addr.isd_id, 1)
        ntools.eq_(addr.ad_id, 10)
        ntools.eq_(addr.host_addr, ip)

    def test(self):
        for ip in IPv4Address("10.1.1.1"), IPv6Address("10:1::10"):
            yield self._check, ip

    @patch("lib.packet.scion_addr.ISD_AD.from_raw", spec_set=[],
           new_callable=MagicMock())
    @patch("lib.packet.scion_addr.Raw", autospec=True)
    def test_len_address(self, raw, isdad_raw):
        # Setup
        raw.return_value = MagicMock(spec_set=["__len__", "pop"])
        raw.return_value.__len__.side_effect = (0, 1)
        isdad_raw.return_value = (1, 10)
        addr = SCIONAddr()
        # Call
        ntools.assert_raises(SCIONParseError, addr.parse, b"data")


class TestSCIONAddrPack(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.pack
    """
    def test_ipv4(self):
        """
        Pack a SCIONAddr containing an IPv4Address.
        """
        isd_id = 1
        ad_id = 10
        host_addr = IPv4Address("10.1.1.1")
        addr = SCIONAddr.from_values(isd_id, ad_id, host_addr)

        isd_ad_bytes = bytes([0, 16, 0, 10])
        addr_bytes = bytes([10, 1, 1, 1])
        ntools.eq_(addr.pack(), isd_ad_bytes + addr_bytes)

    def test_ipv6(self):
        """
        Pack a SCIONAddr containing an IPv6Address.
        """
        isd_id = 1
        ad_id = 10
        host_addr = IPv6Address("10:1::10")
        addr = SCIONAddr.from_values(isd_id, ad_id, host_addr)

        isd_ad_bytes = bytes([0, 16, 0, 10])
        addr_bytes = bytes([0, 16, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16])
        ntools.eq_(addr.pack(), isd_ad_bytes + addr_bytes)


class TestSCIONAddrGetISDAD(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.get_isd_ad
    """
    @patch("lib.packet.scion_addr.ISD_AD", autospec=True)
    def test_basic(self, isd_ad_):
        isd_ad_.return_value = "data"
        addr = SCIONAddr()
        addr.isd_id = "isd_id"
        addr.ad_id = "ad_id"
        ntools.eq_(addr.get_isd_ad(), "data")
        isd_ad_.assert_called_once_with("isd_id", "ad_id")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
