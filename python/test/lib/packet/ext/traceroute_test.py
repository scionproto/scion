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
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.ext.traceroute import TracerouteExt
from test.testcommon import assert_these_calls, create_mock


class TestTracerouteExtParse(object):
    """
    Unit tests for lib.packet.ext.traceroute.TracerouteExt._parse
    """
    @patch("lib.packet.ext.traceroute.ISD_AS", autospec=True)
    @patch("lib.packet.ext.traceroute.HopByHopExtension._parse", autospec=True)
    @patch("lib.packet.ext.traceroute.Raw", autospec=True)
    def test(self, raw, super_parse, isd_as):
        inst = TracerouteExt()
        inst.append_hop = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = (
            None,
            "isd as 1", bytes.fromhex('1111 2222'),
            "isd as 2", bytes.fromhex('3333 4444'),
        )
        raw.return_value = data
        isd_as.LEN = 4
        isd_as.side_effect = "1-11", "2-22"
        dlen = inst.MIN_LEN + 2 * inst.HOP_LEN
        arg = bytes([2]) + bytes(dlen - 1)
        # Call
        inst._parse(arg)
        # Tests
        raw.assert_called_once_with(arg, "TracerouteExt", dlen, min_=True)
        super_parse.assert_called_once_with(inst, data)
        assert_these_calls(isd_as, (call("isd as 1"), call("isd as 2")))
        assert_these_calls(inst.append_hop, (
            call("1-11", 0x1111, 0x2222),
            call("2-22", 0x3333, 0x4444),
        ))


class TestTracerouteExtPack(object):
    """
    Unit tests for lib.packet.ext.traceroute.TracerouteExt.pack
    """
    def test(self):
        inst = TracerouteExt()
        inst._check_len = create_mock()
        inst._hdr_len = 3
        isd_as_1_2 = create_mock(["pack"])
        isd_as_1_2.pack.return_value = b"1-2"
        isd_as_5_6 = create_mock(["pack"])
        isd_as_5_6.pack.return_value = b"5-6"
        inst.hops = [(isd_as_1_2, 3, 4), (isd_as_5_6, 7, 8)]
        expected = b"".join((
            b'\x02', bytes(inst.PADDING_LEN), b'1-2',
            bytes.fromhex('0003 0004'), b'5-6',
            bytes.fromhex('0007 0008')))
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        inst._check_len.assert_called_once_with(expected)


class TestTracerouteExtAppendHop(object):
    """
    Unit tests for lib.packet.ext.traceroute.TracerouteExt.append_hop
    """
    def test(self):
        inst = TracerouteExt()
        inst.hops = [1]
        inst._hdr_len = 3
        # Call
        inst.append_hop("3-4", 5, 6)
        # Tests
        ntools.eq_(inst.hops, [1, ("3-4", 5, 6)])


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
