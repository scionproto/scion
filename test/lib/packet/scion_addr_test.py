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
from lib.packet.host_addr import HostAddrBase
from lib.packet.scion_addr import SCIONAddr, ISD_AD
from test.testcommon import assert_these_call_lists, create_mock


class TestISDADFromRaw(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AD.from_raw
    """
    @patch("lib.packet.scion_addr.Raw", autospec=True)
    def test(self, raw):
        data = create_mock(["pop"])
        data.pop.return_value = bytes.fromhex("11122222")
        raw.return_value = data
        # Call
        inst = ISD_AD.from_raw("data")
        # Tests
        raw.assert_called_once_with("data", ISD_AD.NAME, ISD_AD.LEN)
        ntools.assert_is_instance(inst, ISD_AD)
        ntools.eq_(inst.isd, 0x111)
        ntools.eq_(inst.ad, 0x22222)


class TestISDADPack(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AD.pack
    """
    def test(self):
        inst = ISD_AD(0, 0)
        inst.int = create_mock()
        inst.int.return_value = 0x12345678
        # Call
        ntools.eq_(inst.pack(), bytes.fromhex("12345678"))


class TestISDADInt(object):
    """
    Unit tests for lib.packet.scion_addr.ISD_AD.int
    """
    def test(self):
        inst = ISD_AD(0x111, 0x22222)
        # Call
        ntools.eq_(inst.int(), 0x11122222)


class TestSCIONAddrInit(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.__init__
    """
    @patch("lib.packet.scion_addr.SCIONAddr.parse")
    def test_basic(self, parse):
        # Call
        addr = SCIONAddr()
        # Tests
        ntools.eq_(addr.isd_id, None)
        ntools.eq_(addr.ad_id, None)
        ntools.eq_(addr.host_addr, None)
        ntools.eq_(addr.addr_len, 0)
        ntools.assert_false(parse.called)

    @patch("lib.packet.scion_addr.SCIONAddr.parse")
    def test_raw(self, parse):
        SCIONAddr(("atype", "addr"))
        parse.assert_called_once_with("atype", "addr")


class TestSCIONAddrFromValues(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.from_values
    """
    @patch("lib.packet.scion_addr.SCIONAddr.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        # Setup
        isd_id = 1
        ad_id = 10
        host_addr = create_mock(["__len__"], class_=HostAddrBase)
        host_addr.__len__.return_value = 12
        # Call
        addr = SCIONAddr.from_values(isd_id, ad_id, host_addr)
        # Tests
        ntools.assert_is_instance(addr, SCIONAddr)
        ntools.eq_(addr.isd_id, isd_id)
        ntools.eq_(addr.ad_id, ad_id)
        ntools.eq_(addr.host_addr, host_addr)
        ntools.eq_(addr.addr_len, ISD_AD.LEN + 12)


class TestSCIONAddrParse(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.parse
    """

    @patch("lib.packet.scion_addr.ISD_AD.from_raw",
           new_callable=create_mock)
    @patch("lib.packet.scion_addr.Raw", autospec=True)
    @patch("lib.packet.scion_addr.haddr_get_type", autospec=True)
    @patch("lib.packet.scion_addr.SCIONAddr.__init__", autospec=True,
           return_value=None)
    def test(self, init, get_type, raw, isdad_raw):
        # Setup
        inst = SCIONAddr()
        haddr_type = create_mock(["LEN", "NAME"])
        haddr_type.LEN = 42
        haddr_type.NAME = "NAME"
        get_type.return_value = haddr_type
        data = create_mock(["__len__", "pop"])
        data.pop.side_effect = ("pop isd_ad", "raw addr")
        raw.return_value = data
        isdad_raw.return_value = (1, 10)
        # Call
        inst.parse("atype", "data")
        # Tests
        get_type.assert_called_once_with("atype")
        ntools.eq_(inst.addr_len, 42 + ISD_AD.LEN)
        raw.assert_called_once_with("data", "SCIONAddr (NAME)", 42 + ISD_AD.LEN)
        data.pop.assert_has_calls((call(ISD_AD.LEN), call(42)))
        isdad_raw.assert_called_once_with("pop isd_ad")
        ntools.eq_(inst.isd_id, 1)
        ntools.eq_(inst.ad_id, 10)
        haddr_type.assert_called_once_with("raw addr")
        ntools.eq_(inst.host_addr, haddr_type.return_value)


class TestSCIONAddrPack(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.pack
    """
    @patch("lib.packet.scion_addr.ISD_AD", autospec=True)
    @patch("lib.packet.scion_addr.SCIONAddr.__init__", autospec=True,
           return_value=None)
    def test(self, init, isd_ad):
        inst = SCIONAddr()
        inst.isd_id = 1
        inst.ad_id = 10
        inst.host_addr = create_mock(["pack"])
        inst.host_addr.pack.return_value = "host_addr.packed"
        isd_ad.return_value.pack.return_value = "isd_ad.packed"
        # Call
        ntools.eq_(inst.pack(), "isd_ad.packedhost_addr.packed")
        # Tests
        assert_these_call_lists(isd_ad, [call(1, 10).pack()])


class TestSCIONAddrLen(object):
    """
    Unit tests for lib.packet.scion_addr.SCIONAddr.__len__
    """
    @patch("lib.packet.scion_addr.SCIONAddr.__init__", autospec=True,
           return_value=None)
    def test(self, init):
        inst = SCIONAddr()
        inst.addr_len = 43
        # Call
        ntools.eq_(len(inst), 43)


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
