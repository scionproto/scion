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
:mod:`lib_packet_ext_traceroute_test` --- lib.packet.ext.traceroute unit tests
==============================================================================
"""
# Stdlib
from unittest.mock import patch, MagicMock, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.ext.traceroute import TracerouteExt, traceroute_ext_handler
from test.testcommon import (
    assert_these_call_lists,
    assert_these_calls,
    create_mock,
)


class TestTracerouteExtInit(object):
    """
    Unit tests for lib.packet.ext.traceroute.TracerouteExt.__init__
    """
    @patch("lib.packet.ext.traceroute.TracerouteExt._parse", autospec=True)
    @patch("lib.packet.ext.traceroute.HopByHopExtension.__init__",
           autospec=True)
    def test_basic(self, super_init, set_payload):
        inst = TracerouteExt()
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.eq_(inst.hops, [])

    @patch("lib.packet.ext.traceroute.TracerouteExt._parse", autospec=True)
    @patch("lib.packet.ext.traceroute.HopByHopExtension.__init__",
           autospec=True)
    def test_raw(self, super_init, parse):
        inst = TracerouteExt('data')
        # Tests
        parse.assert_called_once_with(inst, 'data')


class TestTracerouteExtFromValues(object):
    """
    Unit tests for lib.packet.ext.traceroute.TracerouteExt.from_values
    """
    @patch("lib.packet.ext.traceroute.TracerouteExt.update", autospec=True)
    @patch("lib.packet.ext.traceroute.TracerouteExt._init_size", autospec=True)
    def test(self, init_size, update):
        inst = TracerouteExt.from_values(24)
        # Tests
        ntools.assert_is_instance(inst, TracerouteExt)
        init_size.assert_called_once_with(inst, 24)
        update.assert_called_once_with(inst)


class TestTracerouteExtParse(object):
    """
    Unit tests for lib.packet.ext.traceroute.TracerouteExt._parse
    """
    @patch("lib.packet.ext.traceroute.ISD_AD.from_raw",
           new_callable=create_mock)
    @patch("lib.packet.ext.traceroute.Raw", autospec=True)
    @patch("lib.packet.ext.traceroute.HopByHopExtension._parse", autospec=True)
    def test(self, super_parse, raw, isd_ad):
        inst = TracerouteExt()
        inst.append_hop = create_mock()
        inst._raw = b"\x02_raw"
        data = create_mock(["pop"])
        data.pop.side_effect = (
            None,
            "isd ad 1", bytes.fromhex('1111 2222'),
            "isd ad 2", bytes.fromhex('3333 4444'),
        )
        raw.return_value = data
        isd_ad.side_effect = [(1, 11), (2, 22)]
        # Call
        inst._parse("data")
        # Tests
        super_parse.assert_called_once_with(inst, "data")
        raw.assert_called_once_with(b"\x02_raw", "TracerouteExt", 20, min_=True)
        assert_these_calls(isd_ad, (call("isd ad 1"), call("isd ad 2")))
        assert_these_calls(inst.append_hop, (
            call(1, 11, 0x1111, 0x2222),
            call(2, 22, 0x3333, 0x4444),
        ))


class TestTracerouteExtAppendHop(object):
    """
    Unit tests for lib.packet.ext.traceroute.TracerouteExt.append_hop
    """
    @patch("lib.packet.ext.traceroute.TracerouteExt.update", autospec=True)
    def test(self, update):
        inst = TracerouteExt()
        inst.hops = [1]
        inst._hdr_len = 2
        # Call
        inst.append_hop(3, 4, 5, 6)
        # Tests
        ntools.eq_(inst.hops, [1, (3, 4, 5, 6)])
        update.assert_called_once_with(inst)


class TestTracerouteExtUpdate(object):
    """
    Unit tests for lib.packet.ext.traceroute.TracerouteExt.update
    """
    @patch("lib.packet.ext.traceroute.ISD_AD", autospec=True)
    def test(self, isd_ad):
        inst = TracerouteExt()
        inst._set_payload = create_mock()
        inst._hdr_len = 2
        inst.hops = [(1, 2, 3, 4), (5, 6, 7, 8)]
        isd_ad_obj = create_mock(["pack"])
        isd_ad_obj.pack.side_effect = [b'ad_1', b'ad_2']
        isd_ad.return_value = isd_ad_obj
        expected = b"".join((
            b'\x02', bytes(inst.PADDING_LEN), b'ad_1',
            bytes.fromhex('0003 0004'), b'ad_2',
            bytes.fromhex('0007 0008')))
        # Call
        inst.update()
        # Tests
        assert_these_call_lists(isd_ad, [
            call(1, 2).pack(), call(5, 6).pack()])
        inst._set_payload.assert_called_once_with(expected)


class TestTracerouteExtHandler(object):
    """
    Unit tests for lib.packet.ext.traceroute.traceroute_ext_handler
    """
    @patch("lib.util.SCIONTime.get_time", new_callable=create_mock)
    def test(self, get_time):
        get_time.return_value = 0x14fd52f1e85 / 1000
        ext = MagicMock(spec_set=['append_hop'])
        topo = MagicMock(spec_set=['isd_id', 'ad_id'])
        iface = MagicMock(spec_set=['if_id'])
        # Call
        traceroute_ext_handler(ext=ext, topo=topo, iface=iface)
        # Tests
        ext.append_hop.assert_called_once_with(
            topo.isd_id, topo.ad_id, iface.if_id, 0x1e85)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
