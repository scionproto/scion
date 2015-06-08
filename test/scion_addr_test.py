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
:mod:`scion_addr_test` --- SCION address tests
=====================================================
"""
# Stdlib
from ipaddress import IPV4LENGTH, IPV6LENGTH, IPv4Address, IPv6Address
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.scion_addr import SCIONAddr, ISD_AD


class TestSCIONAddrInit(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.__init__
    """
    def test_basic(self):
        addr = SCIONAddr()
        ntools.eq_(addr.isd_id, None)
        ntools.eq_(addr.ad_id, None)
        ntools.eq_(addr.host_addr, None)
        ntools.eq_(addr.addr_len, 0)

    @patch("lib.packet.scion_addr.SCIONAddr.parse")
    def test_raw(self, parse):
        addr = SCIONAddr("data")
        parse.assert_called_once_with("data")


class TestSCIONAddrFromValues(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.from_values
    """
    def test_ipv4(self):
        isd_id = 1
        ad_id = 10
        host_addr = IPv4Address("10.1.1.1")
        addr_len = ISD_AD.LEN + (IPV4LENGTH // 8)

        addr = SCIONAddr.from_values(isd_id, ad_id, host_addr)
        ntools.eq_(addr.isd_id, isd_id)
        ntools.eq_(addr.ad_id, ad_id)
        ntools.eq_(addr.host_addr, host_addr)
        ntools.eq_(addr.addr_len, addr_len)

    def test_ipv6(self):
        isd_id = 1
        ad_id = 10
        host_addr = IPv6Address("2001:db8::1000")
        addr_len = ISD_AD.LEN + (IPV6LENGTH // 8)

        addr = SCIONAddr.from_values(isd_id, ad_id, host_addr)
        ntools.eq_(addr.isd_id, isd_id)
        ntools.eq_(addr.ad_id, ad_id)
        ntools.eq_(addr.host_addr, host_addr)
        ntools.eq_(addr.addr_len, addr_len)


class TestSCIONAddrParse(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.parse
    """
    def test_ipv4(self):
        """
        Parsing a byte stream corresponding to a IPv4Address
        """
        isd_bytes = bytes([0,1])
        ad_bytes = bytes([0,0,0,0,0,0,0,10])
        addr_bytes = bytes([10,1,1,1])
        all_bytes = isd_bytes + ad_bytes + addr_bytes
        addr_len = len(all_bytes)

        addr = SCIONAddr()
        addr.parse(all_bytes)
        ntools.eq_(addr.isd_id, 1)
        ntools.eq_(addr.ad_id, 10)
        ntools.eq_(addr.host_addr, IPv4Address("10.1.1.1"))
        ntools.eq_(addr.addr_len, addr_len)

    def test_ipv6(self):
        """
        Parsing a byte stream corresponding to a IPv6Address
        """
        isd_bytes = bytes([0,1])
        ad_bytes = bytes([0,0,0,0,0,0,0,10])
        addr_bytes = bytes([0,16,0,1,0,0,0,0,0,0,0,0,0,0,0,16])
        all_bytes = isd_bytes + ad_bytes + addr_bytes
        addr_len = len(all_bytes)

        addr = SCIONAddr()
        addr.parse(all_bytes)
        ntools.eq_(addr.isd_id, 1)
        ntools.eq_(addr.ad_id, 10)
        ntools.eq_(addr.host_addr, IPv6Address("10:1::10"))
        ntools.eq_(addr.addr_len, addr_len)

    def test_len(self):
        """
        ISD_AD.LEN is 4 bytes.
        For any byte stream less than this, parsing should not happen properly
        """ 
        addr = SCIONAddr()
        # Byte stream size chosen to be 3
        addr.parse(bytes([0,0,0]))
        ntools.eq_(addr.isd_id, None)
        ntools.eq_(addr.ad_id, None)
        ntools.eq_(addr.host_addr, None)
        ntools.eq_(addr.addr_len, 0)

    def test_len_address(self):
        """
        Byte Stream length is 4+4 for IPv4Address, 4+16 for IPv6Address
        For any byte stream size other than this, parsing should not happen properly
        """ 
        addr = SCIONAddr()
        # Byte stream size chosen to be 11
        addr.parse(bytes([0,0,0,0,0,0,0,0,0,10,0]))
        ntools.eq_(addr.isd_id, 0)
        ntools.eq_(addr.ad_id, 10)
        ntools.eq_(addr.host_addr, None)
        ntools.eq_(addr.addr_len, 0)


class TestSCIONAddrPack(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.pack
    """
    def test_ipv4(self):
        """
        Packing a SCIONAddr containing a IPv4Address
        """
        isd_id = 1
        ad_id = 10
        host_addr = IPv4Address("10.1.1.1")
        addr = SCIONAddr.from_values(isd_id, ad_id, host_addr)

        isd_bytes = bytes([0,1])
        ad_bytes = bytes([0,0,0,0,0,0,0,10])
        addr_bytes = bytes([10,1,1,1])
        ntools.eq_(addr.pack(), isd_bytes + ad_bytes + addr_bytes)

    def test_ipv6(self):
        """
        Packing a SCIONAddr containing a IPv6Address
        """
        isd_id = 1
        ad_id = 10
        host_addr = IPv6Address("10:1::10")
        addr = SCIONAddr.from_values(isd_id, ad_id, host_addr)

        isd_bytes = bytes([0,1])
        ad_bytes = bytes([0,0,0,0,0,0,0,10])
        addr_bytes = bytes([0,16,0,1,0,0,0,0,0,0,0,0,0,0,0,16])
        ntools.eq_(addr.pack(), isd_bytes + ad_bytes + addr_bytes)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
