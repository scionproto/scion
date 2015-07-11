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
:mod:`lib_packet_path_test` --- lib.packet.path unit tests
==========================================================
"""
# Stdlib
import copy
from itertools import product
from unittest.mock import patch, MagicMock, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.path import (
    CorePath,
    CrossOverPath,
    EmptyPath,
    PathBase,
    PathCombinator,
    PeerPath
)
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    OpaqueFieldType)


class BasePath(object):
    def __init__(self):
        self.path = PathBase()
        self.core_path = CorePath()

        # Initialize InfoOpaqueFields as:
        # InfoOpaqueField.from_values(info, up_flag, timestamp, isd_id, hops)
        self.iof = [InfoOpaqueField.from_values(24, True, 45, 18, 3),
                    InfoOpaqueField.from_values(3, False, 9, 65, 5),
                    InfoOpaqueField.from_values(6, False, 29, 51, 3)]

        # Initialize HopOpaqueFields as:
        # HopOpaqueField.from_values(exp_time, ingress_if, egress_if, mac)
        self.hof = [HopOpaqueField.from_values(120, 8, 5, b'\x01\x02\x03'),
                    HopOpaqueField.from_values(140, 5, 56, b'\x04\x05\x06'),
                    HopOpaqueField.from_values(80, 12, 22, b'\x07\x08\x09'),
                    HopOpaqueField.from_values(12, 98, 3, b'\x0A\x0B\x0C'),
                    HopOpaqueField.from_values(90, 235, 55, b'\x0D\x0E\x0F')]

    def __del__(self):
        del self.path
        del self.core_path
        del self.iof
        del self.hof


class TestPathBaseInit(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.__init__
    """
    def test(self):
        """
        Tests proper member initialization.
        """
        ntools.eq_(self.path.up_segment_info, None)
        ntools.eq_(self.path.up_segment_hops, [])
        ntools.eq_(self.path.down_segment_info, None)
        ntools.eq_(self.path.down_segment_hops, [])
        ntools.assert_false(self.path.parsed)


class TestPathBaseReverse(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.reverse
    """
    def test_with_info(self):
        """
        Tests PathBase.reverse, with up_segment_info and down_segment_info set
        """
        self.path.up_segment_info = self.iof[0]
        self.path.down_segment_info = self.iof[1]
        self.path.up_segment_hops = self.hof[:3]
        self.path.down_segment_hops = self.hof[:]
        iof1_ = copy.copy(self.iof[0])
        iof2_ = copy.copy(self.iof[1])
        self.path.reverse()
        iof1_.up_flag ^= True
        iof2_.up_flag ^= True
        ntools.eq_(self.path.up_segment_info, iof2_)
        ntools.eq_(self.path.down_segment_info, iof1_)
        ntools.eq_(self.path.up_segment_hops, self.hof[::-1])
        ntools.eq_(self.path.down_segment_hops, self.hof[2::-1])

    def test_without_info(self):
        """
        Tests PathBase.reverse, with up_segment_info and down_segment_info unset
        """
        self.path.up_segment_hops = self.hof[:3]
        self.path.down_segment_hops = self.hof[:]
        self.path.reverse()
        ntools.eq_(self.path.up_segment_hops, self.hof[::-1])
        ntools.eq_(self.path.down_segment_hops, self.hof[2::-1])


class TestPathBaseGetFirstHopOffset(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.get_first_hop_offset
    """
    def test_with_up_seg_hops(self):
        self.path.up_segment_hops = ['up_hop0']
        ntools.eq_(self.path.get_first_hop_offset(), InfoOpaqueField.LEN)

    def test_with_down_seg_hops(self):
        self.path.up_segment_hops = []
        self.path.down_segment_hops = ['down_hop0']
        ntools.eq_(self.path.get_first_hop_offset(), InfoOpaqueField.LEN)

    def test_without_hops(self):
        self.path.up_segment_hops = []
        self.path.down_segment_hops = []
        ntools.eq_(self.path.get_first_hop_offset(), 0)


class TestPathBaseGetFirstHopOf(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.get_first_hop_of
    """
    @patch("lib.packet.path.PathBase.get_of", autospec=True)
    @patch("lib.packet.path.PathBase.get_first_hop_offset", autospec=True)
    def test_with_hops(self, offset, get_of):
        offset.return_value = 123
        n = (123 - InfoOpaqueField.LEN) // HopOpaqueField.LEN
        get_of.return_value = 'first_hof'
        ntools.eq_(self.path.get_first_hop_of(), 'first_hof')
        offset.assert_called_once_with(self.path)
        get_of.assert_called_once_with(self.path, n + 1)

    @patch("lib.packet.path.PathBase.get_first_hop_offset", autospec=True)
    def test_without_hops(self, offset):
        offset.return_value = 0
        ntools.assert_is_none(self.path.get_first_hop_of())


class TestPathBaseGetFirstInfoOffset(object):
    """
    Unit tests for lib.packet.path.PathBase.get_first_info_offset
    """
    def test(self):
        path = PathBase()
        ntools.eq_(path.get_first_info_offset(), 0)


class TestPathBaseGetFirstInfoOf(object):
    """
    Unit tests for lib.packet.path.PathBase.get_first_info_of
    """
    @patch("lib.packet.path.PathBase.get_of", autospec=True)
    @patch("lib.packet.path.PathBase.get_first_info_offset", autospec=True)
    def test_offset_non_zero(self, offset, get_of):
        path = PathBase()
        offset.return_value = 123
        n = (123 - InfoOpaqueField.LEN) // HopOpaqueField.LEN
        ntools.eq_(path.get_first_info_of(), get_of.return_value)
        offset.assert_called_once_with(path)
        get_of.assert_called_once_with(path, n + 1)

    @patch("lib.packet.path.PathBase.get_of", autospec=True)
    @patch("lib.packet.path.PathBase.get_first_info_offset", autospec=True)
    def test_offset_zero(self, offset, get_of):
        path = PathBase()
        offset.return_value = 0
        ntools.eq_(path.get_first_info_of(), get_of.return_value)
        get_of.assert_called_once_with(path, 0)


class TestPathBaseGetOf(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.get_of
    """
    def _check_full(self, idx, val):
        self.path.up_segment_info = self.iof[0]
        self.path.down_segment_info = self.iof[1]
        self.path.down_segment_hops = self.hof[2:5]
        self.path.up_segment_hops = self.hof[:3]
        ntools.eq_(self.path.get_of(idx), val)

    def test_full(self):
        for i, v in enumerate([self.iof[0]] + self.hof[:3] + [self.iof[1]] +
                              self.hof[2:5] + [None]):
            yield self._check_full, i, v

    def _check_without_up_segment(self, idx, val):
        self.path.up_segment_info = None
        self.path.down_segment_info = self.iof[1]
        self.path.down_segment_hops = self.hof[2:5]
        ntools.eq_(self.path.get_of(idx), val)

    def test_without_up_segment(self):
        for i, v in enumerate([self.iof[1]] + self.hof[2:5]):
            yield self._check_without_up_segment, i, v

    def _check_without_down_segment(self, idx, val):
        self.path.up_segment_info = self.iof[0]
        self.path.up_segment_hops = self.hof[:3]
        self.path.down_segment_info = None
        ntools.eq_(self.path.get_of(idx), val)

    def test_without_down_segment(self):
        for i, v in enumerate([self.iof[0]] + self.hof[:3]):
            yield self._check_without_down_segment, i, v


class TestCorePathInit(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.__init__
    """
    def test_basic(self):
        ntools.eq_(self.core_path.core_segment_info, None)
        ntools.eq_(self.core_path.core_segment_hops, [])

    @patch("lib.packet.path.CorePath.parse", autospec=True)
    def test_raw(self, parse):
        self.core_path = CorePath("data")
        parse.assert_called_once_with(self.core_path, "data")


class TestCorePathParse(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.parse
    """
    @patch("lib.packet.path.CorePath._parse_up_segment", autospec=True)
    def test_with_up_segment(self, parse_up):
        data = bytes.fromhex('0a 0b 0c')
        parse_up.return_value = 3
        self.core_path.parse(data)
        parse_up.assert_called_once_with(self.core_path, data)
        ntools.assert_true(self.core_path.parsed)

    @patch("lib.packet.path.CorePath._parse_core_segment", autospec=True)
    @patch("lib.packet.path.CorePath._parse_up_segment", autospec=True)
    def test_with_core_segment(self, parse_up, parse_core):
        data = bytes.fromhex('0a 0b 0c')
        parse_up.return_value = 1
        parse_core.return_value = 3
        self.core_path.parse(data)
        parse_core.assert_called_once_with(self.core_path, data, 1)
        ntools.assert_true(self.core_path.parsed)

    @patch("lib.packet.path.CorePath._parse_down_segment", autospec=True)
    @patch("lib.packet.path.CorePath._parse_core_segment", autospec=True)
    @patch("lib.packet.path.CorePath._parse_up_segment", autospec=True)
    def test_with_down_segment(self, parse_up, parse_core, parse_down):
        data = bytes.fromhex('0a 0b 0c')
        parse_up.return_value = 1
        parse_core.return_value = 2
        self.core_path.parse(data)
        parse_down.assert_called_once_with(self.core_path, data, 2)
        ntools.assert_true(self.core_path.parsed)

    def test_wrong_type(self):
        ntools.assert_raises(AssertionError, self.core_path.parse, 123)


class TestCorePathParseUpSegment(BasePath):
    """
    Unit tests for lib.packet.path.CorePath._parse_up_segment
    """
    @patch("lib.packet.path.HopOpaqueField", autospec=True)
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def test(self, info_of, hop_of):
        mock_iof = MagicMock(spec_set=['hops'])
        info_of.return_value = mock_iof
        info_of.return_value.hops = 1
        info_of.LEN = InfoOpaqueField.LEN
        hop_of.return_value = 'data1'
        hop_of.LEN = HopOpaqueField.LEN
        data = 'long_data'
        offset = self.core_path._parse_up_segment(data)
        info_of.assert_called_once_with(data[:InfoOpaqueField.LEN])
        hop_of.assert_called_once_with(data[InfoOpaqueField.LEN:
                                            InfoOpaqueField.LEN +
                                            HopOpaqueField.LEN])
        ntools.eq_(self.core_path.up_segment_info, mock_iof)
        ntools.eq_(self.core_path.up_segment_hops, ['data1'])
        ntools.eq_(offset, InfoOpaqueField.LEN + HopOpaqueField.LEN)


class TestCorePathParseCoreSegment(BasePath):
    """
    Unit tests for lib.packet.path.CorePath._parse_core_segment
    """
    @patch("lib.packet.path.HopOpaqueField", autospec=True)
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def test(self, info_of, hop_of):
        mock_iof = MagicMock(spec_set=['hops'])
        info_of.return_value = mock_iof
        info_of.return_value.hops = 1
        info_of.LEN = InfoOpaqueField.LEN
        hop_of.return_value = 'data1'
        hop_of.LEN = HopOpaqueField.LEN
        data = 'long_data'
        offset = self.core_path._parse_core_segment(data, 0)
        info_of.assert_called_once_with(data[:InfoOpaqueField.LEN])
        hop_of.assert_called_once_with(data[InfoOpaqueField.LEN:
                                            InfoOpaqueField.LEN +
                                            HopOpaqueField.LEN])
        ntools.eq_(self.core_path.core_segment_info, mock_iof)
        ntools.eq_(self.core_path.core_segment_hops, ['data1'])
        ntools.eq_(offset, InfoOpaqueField.LEN + HopOpaqueField.LEN)


class TestCorePathParseDownSegment(BasePath):
    """
    Unit tests for lib.packet.path.CorePath._parse_down_segment
    """
    @patch("lib.packet.path.HopOpaqueField", autospec=True)
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def test(self, info_of, hop_of):
        mock_iof = MagicMock(spec_set=['hops'])
        info_of.return_value = mock_iof
        info_of.return_value.hops = 1
        info_of.LEN = InfoOpaqueField.LEN
        hop_of.return_value = 'data1'
        hop_of.LEN = HopOpaqueField.LEN
        data = 'long_data'
        offset = self.core_path._parse_down_segment(data, 0)
        info_of.assert_called_once_with(data[:InfoOpaqueField.LEN])
        hop_of.assert_called_once_with(data[InfoOpaqueField.LEN:
                                            InfoOpaqueField.LEN +
                                            HopOpaqueField.LEN])
        ntools.eq_(self.core_path.down_segment_info, mock_iof)
        ntools.eq_(self.core_path.down_segment_hops, ['data1'])
        ntools.eq_(offset, InfoOpaqueField.LEN + HopOpaqueField.LEN)


class TestCorePathPack(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.pack
    """
    @patch("lib.packet.path.CorePath._pack_down_segment", autospec=True)
    @patch("lib.packet.path.CorePath._pack_core_segment", autospec=True)
    @patch("lib.packet.path.CorePath._pack_up_segment", autospec=True)
    def test(self, pack_up, pack_core, pack_down):
        pack_up.return_value = b'str1'
        pack_core.return_value = b'str2'
        pack_down.return_value = b'str3'
        ntools.eq_(self.core_path.pack(), b'str1' + b'str2' + b'str3')


class TestCorePathPackUpSegment(BasePath):
    """
    Unit tests for lib.packet.path.CorePath._pack_up_segment
    """
    def test_with_info(self):
        self.core_path.up_segment_info = MagicMock(spec_set=['pack'])
        self.core_path.up_segment_info.pack.return_value = b'packed_iof'
        hof_mock = MagicMock(spec_set=['pack'])
        hof_mock.pack.return_value = b'packed_hof'
        self.core_path.up_segment_hops = [hof_mock, hof_mock]
        packed = b'packed_iof' + b'packed_hof' + b'packed_hof'
        ntools.eq_(self.core_path._pack_up_segment(), packed)

    def test_without_info(self):
        self.core_path.up_segment_info = None
        ntools.eq_(self.core_path._pack_up_segment(), b'')


class TestCorePathPackCoreSegment(BasePath):
    """
    Unit tests for lib.packet.path.CorePath._pack_core_segment
    """
    def test_with_info(self):
        self.core_path.core_segment_info = MagicMock(spec_set=['pack'])
        self.core_path.core_segment_info.pack.return_value = b'packed_iof'
        hof_mock = MagicMock(spec_set=['pack'])
        hof_mock.pack.return_value = b'packed_hof'
        self.core_path.core_segment_hops = [hof_mock, hof_mock]
        packed = b'packed_iof' + b'packed_hof' + b'packed_hof'
        ntools.eq_(self.core_path._pack_core_segment(), packed)

    def test_without_info(self):
        self.core_path.core_segment_info = None
        ntools.eq_(self.core_path._pack_core_segment(), b'')


class TestCorePathPackDownSegment(BasePath):
    """
    Unit tests for lib.packet.path.CorePath._pack_down_segment
    """
    def test_with_info(self):
        self.core_path.down_segment_info = MagicMock(spec_set=['pack'])
        self.core_path.down_segment_info.pack.return_value = b'packed_iof'
        hof_mock = MagicMock(spec_set=['pack'])
        hof_mock.pack.return_value = b'packed_hof'
        self.core_path.down_segment_hops = [hof_mock, hof_mock]
        packed = b'packed_iof' + b'packed_hof' + b'packed_hof'
        ntools.eq_(self.core_path._pack_down_segment(), packed)

    def test_without_info(self):
        self.core_path.down_segment_info = None
        ntools.eq_(self.core_path._pack_down_segment(), b'')


class TestCorePathReverse(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    def test_with_info(self, reverse):
        iof1_ = copy.copy(self.iof[0])
        self.core_path.core_segment_info = self.iof[0]
        self.core_path.core_segment_hops = MagicMock(spec_set=['reverse'])
        self.core_path.reverse()
        reverse.assert_called_once_with(self.core_path)
        self.core_path.core_segment_hops.reverse.assert_called_once_with()
        iof1_.up_flag ^= True
        ntools.eq_(self.core_path.core_segment_info, iof1_)

    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    def test_without_info(self, reverse):
        self.core_path.core_segment_hops = MagicMock(spec_set=['reverse'])
        self.core_path.reverse()
        reverse.assert_called_once_with(self.core_path)
        self.core_path.core_segment_hops.reverse.assert_called_once_with()


class TestCorePathGetOf(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.get_of
    """
    def _check(self, idx, val):
        self.core_path.up_segment_info = self.iof[0]
        self.core_path.down_segment_info = self.iof[1]
        self.core_path.core_segment_info = self.iof[2]
        self.core_path.up_segment_hops = self.hof[:2]
        self.core_path.down_segment_hops = [self.hof[2], self.hof[4]]
        self.core_path.core_segment_hops = self.hof[1:4]
        ntools.eq_(self.core_path.get_of(idx), val)

    def test(self):
        for i, v in enumerate([self.iof[0]] + self.hof[:2] + [self.iof[2]] +
                              self.hof[1:4] + [self.iof[1], self.hof[2],
                                               self.hof[4], None]):
            yield self._check, i, v


class TestCorePathFromValues(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.from_values
    """
    def test_basic(self):
        up_hops = self.hof[:2]
        core_hops = self.hof[1:4]
        down_hops = [self.hof[2], self.hof[4]]
        self.core_path = CorePath.from_values(self.iof[0], up_hops, self.iof[1],
                                              core_hops, self.iof[2], down_hops)
        ntools.eq_(self.core_path.up_segment_info, self.iof[0])
        ntools.eq_(self.core_path.core_segment_info, self.iof[1])
        ntools.eq_(self.core_path.down_segment_info, self.iof[2])
        ntools.eq_(self.core_path.up_segment_hops, self.hof[:2])
        ntools.eq_(self.core_path.core_segment_hops, self.hof[1:4])
        ntools.eq_(self.core_path.down_segment_hops, [self.hof[2], self.hof[4]])

    def test_less_arg(self):
        self.core_path = CorePath.from_values()
        ntools.assert_is_none(self.core_path.up_segment_info)
        ntools.assert_is_none(self.core_path.core_segment_info)
        ntools.assert_is_none(self.core_path.down_segment_info)
        ntools.eq_(self.core_path.up_segment_hops, [])
        ntools.eq_(self.core_path.core_segment_hops, [])
        ntools.eq_(self.core_path.down_segment_hops, [])


class TestCrossOverPathInit(object):
    """
    Unit tests for lib.packet.path.CrossOverPath.__init__
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True)
    def test_basic(self, init):
        co_path = CrossOverPath()
        init.assert_called_once_with(co_path)
        ntools.eq_(co_path.up_segment_upstream_ad, None)
        ntools.eq_(co_path.down_segment_upstream_ad, None)

    @patch("lib.packet.path.CrossOverPath.parse", autospec=True)
    def test_raw(self, parse):
        co_path = CrossOverPath("data")
        parse.assert_called_once_with(co_path, "data")


class TestCrossOverPathParse(object):
    """
    Unit tests for lib.packet.path.CrossOverPath.parse
    """
    @patch("lib.packet.path.CrossOverPath._parse_down_segment", autospec=True)
    @patch("lib.packet.path.CrossOverPath._parse_up_segment", autospec=True)
    def test_basic(self, parse_up, parse_down):
        data = bytes.fromhex('0a 0b 0c')
        parse_up.return_value = 1
        co_path = CrossOverPath()
        co_path.parse(data)
        parse_up.assert_called_once_with(co_path, data)
        parse_down.assert_called_once_with(co_path, data, 1)
        ntools.assert_true(co_path.parsed)

    def test_wrong_type(self):
        co_path = CrossOverPath()
        ntools.assert_raises(AssertionError, co_path.parse, 123)


class TestCrossOverPathParseUpSegment(object):
    """
    Unit tests for lib.packet.path.CrossOverPath._parse_up_segment
    """
    @patch("lib.packet.path.HopOpaqueField", autospec=True)
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def test(self, info_of, hop_of):
        mock_iof = MagicMock(spec_set=['hops'])
        info_of.return_value = mock_iof
        info_of.return_value.hops = 1
        info_of.LEN = InfoOpaqueField.LEN
        hop_of.return_value = 'data1'
        hop_of.LEN = HopOpaqueField.LEN
        data = 'some_very_long_data_string'
        co_path = CrossOverPath()
        offset = co_path._parse_up_segment(data)
        info_of.assert_called_once_with(data[:InfoOpaqueField.LEN])
        calls = [call(data[InfoOpaqueField.LEN:InfoOpaqueField.LEN +
                           HopOpaqueField.LEN]),
                 call(data[InfoOpaqueField.LEN + HopOpaqueField.LEN:
                           InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN])]
        hop_of.assert_has_calls(calls)
        ntools.eq_(co_path.up_segment_info, mock_iof)
        ntools.eq_(co_path.up_segment_hops, ['data1'])
        ntools.eq_(co_path.up_segment_upstream_ad, 'data1')
        ntools.eq_(offset, InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN)


class TestCrossOverPathParseDownSegment(object):
    """
    Unit tests for lib.packet.path.CrossOverPath._parse_down_segment
    """
    @patch("lib.packet.path.HopOpaqueField", autospec=True)
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def test(self, info_of, hop_of):
        mock_iof = MagicMock(spec_set=['hops'])
        info_of.return_value = mock_iof
        info_of.return_value.hops = 1
        info_of.LEN = InfoOpaqueField.LEN
        hop_of.return_value = 'data1'
        hop_of.LEN = HopOpaqueField.LEN
        data = 'some_very_long_data_string'
        co_path = CrossOverPath()
        co_path._parse_down_segment(data, 0)
        info_of.assert_called_once_with(data[:InfoOpaqueField.LEN])
        calls = [call(data[InfoOpaqueField.LEN:InfoOpaqueField.LEN +
                           HopOpaqueField.LEN]),
                 call(data[InfoOpaqueField.LEN + HopOpaqueField.LEN:
                           InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN])]
        hop_of.assert_has_calls(calls)
        ntools.eq_(co_path.down_segment_info, mock_iof)
        ntools.eq_(co_path.down_segment_upstream_ad, 'data1')
        ntools.eq_(co_path.down_segment_hops, ['data1'])


class TestCrossOverPathPack(object):
    """
    Unit tests for lib.packet.path.CrossOverPath.pack
    """
    @patch("lib.packet.path.CrossOverPath._pack_down_segment", autospec=True)
    @patch("lib.packet.path.CrossOverPath._pack_up_segment", autospec=True)
    def test(self, pack_up, pack_down):
        co_path = CrossOverPath()
        pack_up.return_value = b'str1'
        pack_down.return_value = b'str2'
        ntools.eq_(co_path.pack(), b'str1' + b'str2')


class TestCrossOverPathPackUpSegment(object):
    """
    Unit tests for lib.packet.path.CrossOverPath._pack_up_segment
    """
    def test(self):
        co_path = CrossOverPath()
        co_path.up_segment_info = MagicMock(spec_set=['pack'])
        co_path.up_segment_info.pack.return_value = b'packed_iof'
        hof_mock = MagicMock(spec_set=['pack'])
        hof_mock.pack.return_value = b'packed_hof'
        co_path.up_segment_hops = [hof_mock, hof_mock]
        co_path.up_segment_upstream_ad = MagicMock(spec_set=['pack'])
        co_path.up_segment_upstream_ad.pack.return_value = b'packed_ad'
        packed = b'packed_iof' + b'packed_hof' + b'packed_hof' + b'packed_ad'
        ntools.eq_(co_path._pack_up_segment(), packed)


class TestCrossOverPathPackDownSegment(object):
    """
    Unit tests for lib.packet.path.CrossOverPath._pack_down_segment
    """
    def test(self):
        co_path = CrossOverPath()
        co_path.down_segment_info = MagicMock(spec_set=['pack'])
        co_path.down_segment_info.pack.return_value = b'packed_iof'
        hof_mock = MagicMock(spec_set=['pack'])
        hof_mock.pack.return_value = b'packed_hof'
        co_path.down_segment_hops = [hof_mock, hof_mock]
        co_path.down_segment_upstream_ad = MagicMock(spec_set=['pack'])
        co_path.down_segment_upstream_ad.pack.return_value = b'packed_ad'
        packed = b'packed_iof' + b'packed_ad' + b'packed_hof' + b'packed_hof'
        ntools.eq_(co_path._pack_down_segment(), packed)


class TestCrossOverPathReverse(object):
    """
    Unit tests for lib.packet.path.CrossOverPath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    def test(self, reverse):
        co_path = CrossOverPath()
        co_path.up_segment_upstream_ad = 1
        co_path.down_segment_upstream_ad = 2
        co_path.reverse()
        reverse.assert_called_once_with(co_path)
        ntools.eq_(co_path.up_segment_upstream_ad, 2)
        ntools.eq_(co_path.down_segment_upstream_ad, 1)


class TestCrossOverPathGetOf(BasePath):
    """
    Unit tests for lib.packet.path.CrossOverPath.get_of
    """
    def _check(self, idx):
        co_path = CrossOverPath()
        co_path.up_segment_info = 0
        co_path.up_segment_hops = [1, 2, 3]
        co_path.up_segment_upstream_ad = 4
        co_path.down_segment_info = 5
        co_path.down_segment_upstream_ad = 6
        co_path.down_segment_hops = [7, 8, 9]
        ntools.eq_(co_path.get_of(idx), idx)

    def test(self):
        for i in range(10):
            yield self._check, i


class TestCrossOverGetFirstHopOffset(object):
    """
    Unit tests for lib.packet.path.CrossOverPath.get_first_hop_offset
    """
    def test_with_up_hops_on_path(self):
        co_path = CrossOverPath()
        co_path.up_segment_hops = ['up_hop0']
        ntools.eq_(co_path.get_first_hop_offset(),
                   2 * InfoOpaqueField.LEN + 3 * HopOpaqueField.LEN)

    def test_with_up_hops(self):
        co_path = CrossOverPath()
        co_path.up_segment_hops = ['up_hop0', 'up_hop1']
        ntools.eq_(co_path.get_first_hop_offset(), InfoOpaqueField.LEN)

    def test_with_down_hops(self):
        co_path = CrossOverPath()
        co_path.down_segment_hops = ['dw_hop0', 'dw_hop1']
        ntools.eq_(co_path.get_first_hop_offset(), InfoOpaqueField.LEN)

    def test_no_hops(self):
        co_path = CrossOverPath()
        ntools.eq_(co_path.get_first_hop_offset(), 0)


class TestCrossOverGetFirstInfoOffset(object):
    """
    Unit tests for lib.packet.path.CrossOverPath.get_first_info_offset
    """
    def test_on_path(self):
        co_path = CrossOverPath()
        co_path.up_segment_hops = ['up_hop0']
        ntools.eq_(co_path.get_first_info_offset(),
                   InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN)

    def test_not_on_path(self):
        co_path = CrossOverPath()
        co_path.up_segment_hops = ['up_hop0', 'up_hop0']
        ntools.eq_(co_path.get_first_info_offset(), 0)

    def test_no_up_hops(self):
        co_path = CrossOverPath()
        ntools.eq_(co_path.get_first_info_offset(), 0)


class TestPeerPathInit(object):
    """
    Unit tests for lib.packet.path.PeerPath.__init__
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True)
    def test_basic(self, init):
        peer_path = PeerPath()
        init.assert_called_once_with(peer_path)
        ntools.assert_is_none(peer_path.up_segment_peering_link)
        ntools.assert_is_none(peer_path.up_segment_upstream_ad)
        ntools.assert_is_none(peer_path.down_segment_peering_link)
        ntools.assert_is_none(peer_path.down_segment_upstream_ad)

    @patch("lib.packet.path.PeerPath.parse", autospec=True)
    def test_raw(self, parse):
        peer_path = PeerPath('rawstring')
        parse.assert_called_once_with(peer_path, 'rawstring')


class TestPeerPathParse(object):
    """
    Unit tests for lib.packet.path.PeerPath.parse
    """
    @patch("lib.packet.path.PeerPath._parse_down_segment", autospec=True)
    @patch("lib.packet.path.PeerPath._parse_up_segment", autospec=True)
    def test_basic(self, parse_up, parse_down):
        data = bytes.fromhex('0a 0b 0c')
        parse_up.return_value = 1
        peer_path = PeerPath()
        peer_path.parse(data)
        parse_up.assert_called_once_with(peer_path, data)
        parse_down.assert_called_once_with(peer_path, data, 1)
        ntools.assert_true(peer_path.parsed)

    def test_wrong_type(self):
        peer_path = PeerPath()
        ntools.assert_raises(AssertionError, peer_path.parse, 123)


class TestPeerPathParseUpSegment(object):
    """
    Unit tests for lib.packet.path.PeerPath._parse_up_segment
    """
    @patch("lib.packet.path.HopOpaqueField", autospec=True)
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def test(self, info_of, hop_of):
        mock_iof = MagicMock(spec_set=['hops'])
        info_of.return_value = mock_iof
        info_of.return_value.hops = 1
        info_of.LEN = InfoOpaqueField.LEN
        hop_of.return_value = 'data1'
        hop_of.LEN = HopOpaqueField.LEN
        data = 'some_oh_very_very_long_data_string'
        peer_path = PeerPath()
        offset = peer_path._parse_up_segment(data)
        info_of.assert_called_once_with(data[:InfoOpaqueField.LEN])
        calls = [call(data[InfoOpaqueField.LEN:InfoOpaqueField.LEN +
                           HopOpaqueField.LEN]),
                 call(data[InfoOpaqueField.LEN + HopOpaqueField.LEN:
                           InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN]),
                 call(data[InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN:
                           InfoOpaqueField.LEN + 3 * HopOpaqueField.LEN])]
        hop_of.assert_has_calls(calls)
        ntools.eq_(peer_path.up_segment_info, mock_iof)
        ntools.eq_(peer_path.up_segment_hops, ['data1'])
        ntools.eq_(peer_path.up_segment_peering_link, 'data1')
        ntools.eq_(peer_path.up_segment_upstream_ad, 'data1')
        ntools.eq_(offset, InfoOpaqueField.LEN + 3 * HopOpaqueField.LEN)


class TestPeerPathParseDownSegment(object):
    """
    Unit tests for lib.packet.path.PeerPath._parse_down_segment
    """
    @patch("lib.packet.path.HopOpaqueField", autospec=True)
    @patch("lib.packet.path.InfoOpaqueField", autospec=True)
    def test(self, info_of, hop_of):
        mock_iof = MagicMock(spec_set=['hops'])
        info_of.return_value = mock_iof
        info_of.return_value.hops = 1
        info_of.LEN = InfoOpaqueField.LEN
        hop_of.return_value = 'data1'
        hop_of.LEN = HopOpaqueField.LEN
        data = 'some_oh_very_very_long_data_string'
        peer_path = PeerPath()
        peer_path._parse_down_segment(data, 0)
        info_of.assert_called_once_with(data[:InfoOpaqueField.LEN])
        calls = [call(data[InfoOpaqueField.LEN:InfoOpaqueField.LEN +
                           HopOpaqueField.LEN]),
                 call(data[InfoOpaqueField.LEN + HopOpaqueField.LEN:
                           InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN]),
                 call(data[InfoOpaqueField.LEN + 2 * HopOpaqueField.LEN:
                           InfoOpaqueField.LEN + 3 * HopOpaqueField.LEN])]
        hop_of.assert_has_calls(calls)
        ntools.eq_(peer_path.down_segment_info, mock_iof)
        ntools.eq_(peer_path.down_segment_upstream_ad, 'data1')
        ntools.eq_(peer_path.down_segment_peering_link, 'data1')
        ntools.eq_(peer_path.down_segment_hops, ['data1'])


class TestPeerPathPack(object):
    """
    Unit tests for lib.packet.path.PeerPath.pack
    """
    @patch("lib.packet.path.PeerPath._pack_down_segment", autospec=True)
    @patch("lib.packet.path.PeerPath._pack_up_segment", autospec=True)
    def test(self, pack_up, pack_down):
        peer_path = PeerPath()
        pack_up.return_value = b'str1'
        pack_down.return_value = b'str2'
        ntools.eq_(peer_path.pack(), b'str1' + b'str2')


class TestPeerPathPackUpSegment(object):
    """
    Unit tests for lib.packet.path.PeerPath._pack_up_segment
    """
    def test(self):
        peer_path = PeerPath()
        peer_path.up_segment_info = MagicMock(spec_set=['pack'])
        peer_path.up_segment_info.pack.return_value = b'packed_iof'
        hof_mock = MagicMock(spec_set=['pack'])
        hof_mock.pack.return_value = b'packed_hof'
        peer_path.up_segment_hops = [hof_mock, hof_mock]
        peer_path.up_segment_upstream_ad = MagicMock(spec_set=['pack'])
        peer_path.up_segment_upstream_ad.pack.return_value = b'packed_ad'
        peer_path.up_segment_peering_link = MagicMock(spec_set=['pack'])
        peer_path.up_segment_peering_link.pack.return_value = b'packed_link'
        packed = b'packed_iof' + b'packed_hof' + b'packed_hof' + \
                 b'packed_link' + b'packed_ad'
        ntools.eq_(peer_path._pack_up_segment(), packed)


class TestPeerPathPackDownSegment(object):
    """
    Unit tests for lib.packet.path.PeerPath._pack_down_segment
    """
    def test(self):
        peer_path = PeerPath()
        peer_path.down_segment_info = MagicMock(spec_set=['pack'])
        peer_path.down_segment_info.pack.return_value = b'packed_iof'
        hof_mock = MagicMock(spec_set=['pack'])
        hof_mock.pack.return_value = b'packed_hof'
        peer_path.down_segment_hops = [hof_mock, hof_mock]
        peer_path.down_segment_upstream_ad = MagicMock(spec_set=['pack'])
        peer_path.down_segment_upstream_ad.pack.return_value = b'packed_ad'
        peer_path.down_segment_peering_link = MagicMock(spec_set=['pack'])
        peer_path.down_segment_peering_link.pack.return_value = b'packed_link'
        packed = b'packed_iof' + b'packed_ad' + b'packed_link' + \
                 b'packed_hof' + b'packed_hof'
        ntools.eq_(peer_path._pack_down_segment(), packed)


class TestPeerPathReverse(object):
    """
    Unit tests for lib.packet.path.PeerPath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse", autospec=True)
    def test(self, reverse):
        peer_path = PeerPath()
        peer_path.up_segment_upstream_ad = 1
        peer_path.down_segment_upstream_ad = 2
        peer_path.up_segment_peering_link = 3
        peer_path.down_segment_peering_link = 4
        peer_path.reverse()
        reverse.assert_called_once_with(peer_path)
        ntools.eq_(peer_path.up_segment_upstream_ad, 2)
        ntools.eq_(peer_path.down_segment_upstream_ad, 1)
        ntools.eq_(peer_path.up_segment_peering_link, 4)
        ntools.eq_(peer_path.down_segment_peering_link, 3)


class TestPeerPathGetOf(BasePath):
    """
    Unit tests for lib.packet.path.PeerPath.get_of
    """
    def _check(self, idx):
        peer_path = PeerPath()
        peer_path.up_segment_info = 0
        peer_path.up_segment_hops = [1, 2, 3]
        peer_path.up_segment_peering_link = 4
        peer_path.up_segment_upstream_ad = 5
        peer_path.down_segment_info = 6
        peer_path.down_segment_upstream_ad = 7
        peer_path.down_segment_peering_link = 8
        peer_path.down_segment_hops = [9, 10, 11]
        ntools.eq_(peer_path.get_of(idx), idx)

    def test(self):
        for i in range(12):
            yield self._check, i


class TestPeerPathGetFirstHopOffset(object):
    """
    Unit tests for lib.packet.path.PeerPath.get_first_hop_offset
    """
    def test_with_up_seg_hops_last(self):
        peer_path = PeerPath()
        peer_path.up_segment_hops = [MagicMock(spec_set=['info'])]
        peer_path.up_segment_hops[0].info = OpaqueFieldType.LAST_OF
        ntools.eq_(peer_path.get_first_hop_offset(),
                   InfoOpaqueField.LEN + HopOpaqueField.LEN)

    def test_with_up_seg_hops(self):
        peer_path = PeerPath()
        peer_path.up_segment_hops = [MagicMock(spec_set=['info'])]
        peer_path.up_segment_hops[0].info = 123
        ntools.eq_(peer_path.get_first_hop_offset(), InfoOpaqueField.LEN)

    def test_with_down_seg_hops_last(self):
        peer_path = PeerPath()
        peer_path.down_segment_hops = [MagicMock(spec_set=['info'])]
        peer_path.down_segment_hops[0].info = OpaqueFieldType.LAST_OF
        ntools.eq_(peer_path.get_first_hop_offset(),
                   InfoOpaqueField.LEN + HopOpaqueField.LEN)

    def test_with_down_seg_hops(self):
        peer_path = PeerPath()
        peer_path.down_segment_hops = [MagicMock(spec_set=['info'])]
        peer_path.down_segment_hops[0].info = 123
        ntools.eq_(peer_path.get_first_hop_offset(), InfoOpaqueField.LEN)

    def test_without_hops(self):
        peer_path = PeerPath()
        ntools.eq_(peer_path.get_first_hop_offset(), 0)


class TestEmptyPathInit(object):
    """
    Unit tests for lib.packet.path.EmptyPath.__init__
    """
    @patch("lib.packet.path.PathBase.__init__", autospec=True)
    def test_basic(self, init):
        empty_path = EmptyPath()
        init.assert_called_once_with(empty_path)


class TestEmptyPathPack(object):
    """
    Unit tests for lib.packet.path.EmptyPath.pack
    """
    def test(self):
        empty_path = EmptyPath()
        ntools.eq_(empty_path.pack(), b'')


class TestEmptyPathGetFirstHopOf(object):
    """
    Unit tests for lib.packet.path.EmptyPath.get_first_hop_of
    """
    def test(self):
        empty_path = EmptyPath()
        ntools.assert_is_none(empty_path.get_first_hop_of())


class TestEmptyPathGetOf(object):
    """
    Unit tests for lib.packet.path.EmptyPath.get_of
    """
    def test(self):
        empty_path = EmptyPath()
        empty_path.up_segment_info = 1
        ntools.assert_is_none(empty_path.get_of(123))


class TestPathCombinatorBuildShortcutPaths(object):
    """
    Unit tests for lib.packet.path.PathCombinator.build_shortcut_paths
    """
    @patch("lib.packet.path.PathCombinator._build_shortcut_path",
           spec_set=[], new_callable=MagicMock)
    def test(self, build_path):
        up_segments = ['up0', 'up1']
        down_segments = ['down0', 'down1']
        build_path.side_effect = ['path0', 'path1', 'path1', None]
        paths = ['path0', 'path1']
        ntools.eq_(PathCombinator.build_shortcut_paths(up_segments,
                                                       down_segments), paths)
        calls = [call(*x) for x in product(up_segments, down_segments)]
        build_path.assert_has_calls(calls)


class TestPathCombinatorBuildCorePaths(object):
    """
    Unit tests for lib.packet.path.PathCombinator.build_core_paths
    """
    @patch("lib.packet.path.PathCombinator._build_core_path",
           spec_set=[], new_callable=MagicMock)
    def test_without_core(self, build_path):
        build_path.return_value = 'path0'
        ntools.eq_(PathCombinator.build_core_paths('up', 'down', None),
                   ['path0'])
        build_path.assert_called_once_with('up', [], 'down')

    @patch("lib.packet.path.PathCombinator._build_core_path",
           spec_set=[], new_callable=MagicMock)
    def test_empty_without_core(self, build_path):
        build_path.return_value = None
        ntools.eq_(PathCombinator.build_core_paths('up', 'down', None), [])

    @patch("lib.packet.path.PathCombinator._build_core_path",
           spec_set=[], new_callable=MagicMock)
    def test_with_core(self, build_path):
        core_segments = ['core0', 'core1', 'core2', 'core3']
        build_path.side_effect = ['path0', 'path1', 'path1', None]
        ntools.eq_(PathCombinator.build_core_paths('up', 'down', core_segments),
                   ['path0', 'path1'])
        calls = [call('up', cs, 'down') for cs in core_segments]
        build_path.assert_has_calls(calls)


class TestPathCombinatorBuildShortcutPath(object):
    """
    Unit tests for lib.packet.path.PathCombinator._build_shortcut_path
    """
    def setUp(self):
        self.up_seg = MagicMock(spec_set=['ads'])
        self.up_seg.ads = [123]
        self.down_seg = MagicMock(spec_set=['ads'])
        self.down_seg.ads = [456]

    def tearDown(self):
        del self.up_seg
        del self.down_seg

    def _check_none(self, up_seg, down_seg):
        ntools.assert_is_none(PathCombinator._build_shortcut_path(up_seg,
                                                                  down_seg))

    def test_none(self):
        up_segs = [[], [1], MagicMock(spec_set=['ads']),
                   MagicMock(spec_set=['ads'])]
        up_segs[2].ads = []
        up_segs[3].ads = [456]
        down_segs = [123, [], [2], MagicMock(spec_set=['ads'])]
        down_segs[3].ads = []
        for up_seg, down_seg in zip(up_segs, down_segs):
            yield self._check_none, up_seg, down_seg

    @patch("lib.packet.path.PathCombinator._get_xovrs_peers", spec_set=[],
           new_callable=MagicMock)
    def test_no_xovrs_peers(self, get_xovrs_peers):
        get_xovrs_peers.return_value = [], []
        ntools.assert_is_none(PathCombinator._build_shortcut_path(
            self.up_seg, self.down_seg))
        get_xovrs_peers.assert_called_once_with(self.up_seg, self.down_seg)

    @patch("lib.packet.path.PathCombinator._join_shortcuts", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.path.PathCombinator._get_xovrs_peers", spec_set=[],
           new_callable=MagicMock)
    def _check_xovrs_peers(self, xovrs, peers, point, peer, get_xovrs_peers,
                           join_shortcuts):
        get_xovrs_peers.return_value = xovrs, peers
        join_shortcuts.return_value = 'path'
        ntools.eq_(PathCombinator._build_shortcut_path(self.up_seg,
                                                       self.down_seg), 'path')
        join_shortcuts.assert_called_once_with(self.up_seg, self.down_seg,
                                               point, peer)

    def test_with_peers(self):
        xovrs_list = [[1, [2, 3, 4]], []]
        peers_list = [[5, [6, 7, 8]]] * 2
        for xovrs, peers in zip(xovrs_list, peers_list):
            yield self._check_xovrs_peers, xovrs, peers, [6, 7, 8], True

    def test_with_xovrs(self):
        xovrs_list = [[3, [5, 7, 9]]] * 2
        peers_list = [[1, [2, 4, 6]], []]
        for xovrs, peers in zip(xovrs_list, peers_list):
            yield self._check_xovrs_peers, xovrs, peers, [5, 7, 9], False


class TestPathCombinatorBuildCorePath(object):
    """
    Unit tests for lib.packet.path.PathCombinator._build_core_path
    """
    def setUp(self):
        self.up_seg = MagicMock(spec_set=['ads'])
        self.up_seg.ads = [123]
        self.down_seg = MagicMock(spec_set=['ads'])
        self.down_seg.ads = [456]

    def tearDown(self):
        del self.up_seg
        del self.down_seg

    def _check_none(self, up_seg, down_seg):
        ntools.assert_is_none(PathCombinator._build_core_path(
            up_seg, 'core_seg', down_seg))

    def test_none(self):
        up_segs = [[], [1], MagicMock(spec_set=['ads']),
                   MagicMock(spec_set=['ads'])]
        up_segs[2].ads = []
        up_segs[3].ads = [456]
        down_segs = [123, [], [2], MagicMock(spec_set=['ads'])]
        down_segs[3].ads = []
        for up_seg, down_seg in zip(up_segs, down_segs):
            yield self._check_none, up_seg, down_seg

    @patch("lib.packet.path.PathCombinator._check_connected", spec_set=[],
           new_callable=MagicMock)
    def test_not_connected(self, check_connected):
        check_connected.return_value = False
        ntools.assert_is_none(PathCombinator._build_core_path(
            self.up_seg, 'core_seg', self.down_seg))
        check_connected.assert_called_once_with(self.up_seg, 'core_seg',
                                                self.down_seg)

    @patch("lib.packet.path.PathCombinator._join_down_segment", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.path.PathCombinator._join_core_segment", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.path.PathCombinator._join_up_segment", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.path.CorePath", autospec=True)
    @patch("lib.packet.path.PathCombinator._check_connected", spec_set=[],
           new_callable=MagicMock)
    def test_full(self, check_connected, core_path, join_up, join_core,
                  join_down):
        check_connected.return_value = True
        core_path.return_value = 'core_path'
        join_up.return_value = 'up_join'
        join_core.return_value = 'core_join'
        join_down.return_value = 'down_join'
        ntools.eq_(PathCombinator._build_core_path(self.up_seg, 'core_seg',
                                                   self.down_seg), 'down_join')
        core_path.assert_called_once_with()
        join_up.assert_called_once_with('core_path', self.up_seg)
        join_core.assert_called_once_with('up_join', 'core_seg')
        join_down.assert_called_once_with('core_join', self.down_seg)


class TestPathCombinatorGetXovrsPeers(object):
    """
    Unit tests for lib.packet.path.PathCombinator._get_xovrs_peers
    """
    def test(self):
        up_seg = MagicMock(spec_set=['ads'])
        down_seg = MagicMock(spec_set=['ads'])
        up_seg.ads = [MagicMock(spec_set=['pcbm', 'pms']) for i in range(5)]
        down_seg.ads = [MagicMock(spec_set=['pcbm', 'pms']) for i in range(7)]
        for up_ad in up_seg.ads:
            up_ad.pcbm = MagicMock(spec_set=['ad_id'])
        for down_ad in down_seg.ads:
            down_ad.pcbm = MagicMock(spec_set=['ad_id'])
        # for xovrs
        up_seg.ads[1].pcbm.ad_id = down_seg.ads[6].pcbm.ad_id = 1
        up_seg.ads[3].pcbm.ad_id = down_seg.ads[2].pcbm.ad_id = 3

        # for peers
        up_seg.ads[2].pms = [MagicMock(spec_set=['ad_id']) for i in range(3)]
        up_seg.ads[4].pms = [MagicMock(spec_set=['ad_id']) for i in range(2)]
        down_seg.ads[5].pms = [MagicMock(spec_set=['ad_id']) for i in range(3)]
        down_seg.ads[1].pms = [MagicMock(spec_set=['ad_id']) for i in range(4)]
        up_seg.ads[2].pms[1].ad_id = down_seg.ads[5].pcbm.ad_id = 4
        down_seg.ads[5].pms[2].ad_id = up_seg.ads[2].pcbm.ad_id = 5
        up_seg.ads[4].pms[0].ad_id = down_seg.ads[1].pcbm.ad_id = 6
        down_seg.ads[1].pms[1].ad_id = up_seg.ads[4].pcbm.ad_id = 7

        xovrs, peers = PathCombinator._get_xovrs_peers(up_seg, down_seg)
        ntools.eq_(xovrs, [(3, 2), (1, 6)])
        ntools.eq_(peers, [(4, 1), (2, 5)])


class TestPathCombinatorJoinShortcuts(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_shortcuts
    """
    @patch("lib.packet.path.PathCombinator._join_down_segment_shortcuts",
           spec_set=[], new_callable=MagicMock)
    @patch("lib.packet.path.PathCombinator._join_up_segment_shortcuts",
           spec_set=[], new_callable=MagicMock)
    @patch("lib.packet.path.CrossOverPath", autospec=True)
    @patch("lib.packet.path.copy.deepcopy", spec_set=[], new_callable=MagicMock)
    def test_not_peer(self, deepcopy, cross_over_path, join_up, join_down):
        deepcopy.side_effect = ['up_seg_cpy', 'dw_seg_cpy']
        point = (2, 5)
        cross_over_path.return_value = 'cross_over_path'
        join_up.return_value = 'up_joined'
        join_down.return_value = 'down_joined'
        ntools.eq_(PathCombinator._join_shortcuts('up_seg', 'dw_seg', point,
                                                  False), 'down_joined')
        deepcopy.assert_has_calls([call('up_seg'), call('dw_seg')])
        cross_over_path.assert_called_once_with()
        join_up.assert_called_once_with('cross_over_path', 'up_seg_cpy',
                                        OpaqueFieldType.NON_TDC_XOVR, 2)
        join_down.assert_called_once_with('up_joined', 'dw_seg_cpy',
                                          OpaqueFieldType.NON_TDC_XOVR, 5)

    @patch("lib.packet.path.PathCombinator._join_down_segment_shortcuts",
           spec_set=[], new_callable=MagicMock)
    @patch("lib.packet.path.PathCombinator._join_shortcuts_peer",
           spec_set=[], new_callable=MagicMock)
    @patch("lib.packet.path.PathCombinator._join_up_segment_shortcuts",
           spec_set=[], new_callable=MagicMock)
    @patch("lib.packet.path.PeerPath", autospec=True)
    @patch("lib.packet.path.copy.deepcopy", spec_set=[], new_callable=MagicMock)
    def test_peer_intra(self, deepcopy, peer_path, join_up, join_peer,
                        join_down):
        up_seg_cpy = MagicMock(spec_set=['get_isd', 'ads'])
        up_seg_cpy.get_isd.return_value = 123
        up_seg_cpy.ads = ['up_ad' + str(i) for i in range(6)]
        dw_seg_cpy = MagicMock(spec_set=['get_isd', 'ads'])
        dw_seg_cpy.get_isd.return_value = 123
        dw_seg_cpy.ads = ['dw_ad' + str(i) for i in range(6)]
        deepcopy.side_effect = [up_seg_cpy, dw_seg_cpy]
        point = (2, 5)
        peer_path.return_value = 'peer_path'
        join_up.return_value = 'up_joined'
        join_peer.return_value = 'peer_joined'
        join_down.return_value = 'down_joined'
        ntools.eq_(PathCombinator._join_shortcuts('up_seg', 'dw_seg', point,
                                                  True), 'down_joined')
        peer_path.assert_called_once_with()
        join_up.assert_called_once_with('peer_path', up_seg_cpy,
                                        OpaqueFieldType.INTRATD_PEER, 2)
        join_peer.assert_called_once_with('up_joined', up_seg_cpy.ads[2],
                                          dw_seg_cpy.ads[5])
        join_down.assert_called_once_with('peer_joined', dw_seg_cpy,
                                          OpaqueFieldType.INTRATD_PEER, 5)

    @patch("lib.packet.path.PathCombinator._join_down_segment_shortcuts",
           spec_set=[], new_callable=MagicMock)
    @patch("lib.packet.path.PathCombinator._join_shortcuts_peer",
           spec_set=[], new_callable=MagicMock)
    @patch("lib.packet.path.PathCombinator._join_up_segment_shortcuts",
           spec_set=[], new_callable=MagicMock)
    @patch("lib.packet.path.PeerPath", autospec=True)
    @patch("lib.packet.path.copy.deepcopy", spec_set=[], new_callable=MagicMock)
    def test_peer_inter(self, deepcopy, peer_path, join_up, join_peer,
                        join_down):
        up_seg_cpy = MagicMock(spec_set=['get_isd', 'ads'])
        up_seg_cpy.get_isd.return_value = 123
        up_seg_cpy.ads = ['up_ad' + str(i) for i in range(6)]
        dw_seg_cpy = MagicMock(spec_set=['get_isd', 'ads'])
        dw_seg_cpy.get_isd.return_value = 456
        dw_seg_cpy.ads = ['dw_ad' + str(i) for i in range(6)]
        deepcopy.side_effect = [up_seg_cpy, dw_seg_cpy]
        point = (2, 5)
        peer_path.return_value = 'peer_path'
        join_peer.return_value = 'peer_joined'
        join_down.return_value = 'down_joined'
        ntools.eq_(PathCombinator._join_shortcuts('up_seg', 'dw_seg', point,
                                                  True), 'down_joined')
        join_up.assert_called_once_with('peer_path', up_seg_cpy,
                                        OpaqueFieldType.INTERTD_PEER, 2)
        join_down.assert_called_once_with('peer_joined', dw_seg_cpy,
                                          OpaqueFieldType.INTERTD_PEER, 5)


class TestPathCombinatorCheckConnected(object):
    """
    Unit tests for lib.packet.path.PathCombinator._check_connected
    """
    def setUp(self):
        self.core_seg = MagicMock(spec_set=['get_last_pcbm', 'get_first_pcbm'])
        self.core_seg.get_last_pcbm.return_value = MagicMock(spec_set=['ad_id'])
        self.core_seg.get_first_pcbm.return_value = \
            MagicMock(spec_set=['ad_id'])
        self.up_seg = MagicMock(spec_set=['get_first_pcbm'])
        self.up_seg.get_first_pcbm.return_value = MagicMock(spec_set=['ad_id'])
        self.down_seg = MagicMock(spec_set=['get_first_pcbm'])
        self.down_seg.get_first_pcbm.return_value = \
            MagicMock(spec_set=['ad_id'])

    def tearDown(self):
        del self.core_seg
        del self.up_seg
        del self.down_seg

    def test_up_seg_disconnected(self):
        self.core_seg.get_last_pcbm.return_value.ad_id = 123
        self.up_seg.get_first_pcbm.return_value.ad_id = 456
        ntools.assert_false(PathCombinator._check_connected(self.up_seg,
                                                            self.core_seg,
                                                            'down_seg'))

    def test_down_seg_disconnected(self):
        self.core_seg.get_last_pcbm.return_value.ad_id = 123
        self.up_seg.get_first_pcbm.return_value.ad_id = 123
        self.core_seg.get_first_pcbm.return_value.ad_id = 456
        self.down_seg.get_first_pcbm.return_value.ad_id = 789
        ntools.assert_false(PathCombinator._check_connected(self.up_seg,
                                                            self.core_seg,
                                                            self.down_seg))

    def test_connected_with_core(self):
        self.core_seg.get_last_pcbm.return_value.ad_id = 123
        self.up_seg.get_first_pcbm.return_value.ad_id = 123
        self.core_seg.get_first_pcbm.return_value.ad_id = 456
        self.down_seg.get_first_pcbm.return_value.ad_id = 456
        ntools.assert_true(PathCombinator._check_connected(self.up_seg,
                                                           self.core_seg,
                                                           self.down_seg))

    def test_disconnected_without_core(self):
        self.up_seg.get_first_pcbm.return_value.ad_id = 123
        self.down_seg.get_first_pcbm.return_value.ad_id = 456
        ntools.assert_false(PathCombinator._check_connected(self.up_seg,
                                                            None,
                                                            self.down_seg))

    def test_connected_without_core(self):
        self.up_seg.get_first_pcbm.return_value.ad_id = 123
        self.down_seg.get_first_pcbm.return_value.ad_id = 123
        ntools.assert_true(PathCombinator._check_connected(self.up_seg,
                                                           None, self.down_seg))


class TestPathCombinatorJoinUpSegment(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_up_segment
    """
    @patch("lib.packet.path.copy.deepcopy", spec_set=[], new_callable=MagicMock)
    def test(self, deepcopy):
        path = MagicMock(spec_set=['up_segment_info', 'up_segment_hops'])
        path.up_segment_hops = [5, 6]
        up_segment = MagicMock(spec_set=['iof', 'ads'])
        up_segment.iof = MagicMock(spec_set=['up_flag'])
        up_segment.ads = [MagicMock(spec_set=['pcbm']) for i in range(3)]
        for i, block in enumerate(up_segment.ads):
            block.pcbm = MagicMock(spec_set=['hof'])
            block.pcbm.hof = i
        last_hop = MagicMock(spec_set=['info'])
        deepcopy.side_effect = ['1', '2', last_hop]
        path_ = PathCombinator._join_up_segment(path, up_segment)
        ntools.eq_(path_.up_segment_info, up_segment.iof)
        ntools.assert_true(path_.up_segment_info.up_flag)
        ntools.eq_(path_.up_segment_hops, [5, 6, '1', '2', last_hop])
        deepcopy.assert_has_calls([call(2), call(1), call(0)])
        ntools.eq_(path_.up_segment_hops[-1].info, OpaqueFieldType.LAST_OF)


class TestPathCombinatorJoinCoreSegment(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_core_segment
    """
    def test_none(self):
        ntools.eq_(PathCombinator._join_core_segment('path', None), 'path')

    @patch("lib.packet.path.copy.deepcopy", spec_set=[], new_callable=MagicMock)
    def test(self, deepcopy):
        path = MagicMock(spec_set=['core_segment_info', 'core_segment_hops'])
        first_hop = MagicMock(spec_set=['info'])
        path.core_segment_hops = [first_hop, 6]
        core_segment = MagicMock(spec_set=['iof', 'ads'])
        core_segment.iof = MagicMock(spec_set=['up_flag'])
        core_segment.ads = [MagicMock(spec_set=['pcbm']) for i in range(3)]
        for i, block in enumerate(core_segment.ads):
            block.pcbm = MagicMock(spec_set=['hof'])
            block.pcbm.hof = i
        last_hop = MagicMock(spec_set=['info'])
        deepcopy.side_effect = ['1', '2', last_hop]
        path_ = PathCombinator._join_core_segment(path, core_segment)
        ntools.eq_(path_.core_segment_info, core_segment.iof)
        ntools.assert_true(path_.core_segment_info.up_flag)
        ntools.eq_(path_.core_segment_hops, [first_hop, 6, '1', '2', last_hop])
        deepcopy.assert_has_calls([call(2), call(1), call(0)])
        ntools.eq_(path_.core_segment_hops[-1].info, OpaqueFieldType.LAST_OF)
        ntools.eq_(path_.core_segment_hops[0].info, OpaqueFieldType.LAST_OF)


class TestPathCombinatorJoinDownSegment(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_down_segment
    """
    @patch("lib.packet.path.copy.deepcopy", spec_set=[], new_callable=MagicMock)
    def test(self, deepcopy):
        path = MagicMock(spec_set=['down_segment_info', 'down_segment_hops'])
        first_hop = MagicMock(spec_set=['info'])
        path.down_segment_hops = [first_hop, 6]
        down_segment = MagicMock(spec_set=['iof', 'ads'])
        down_segment.iof = MagicMock(spec_set=['up_flag'])
        down_segment.ads = [MagicMock(spec_set=['pcbm']) for i in range(3)]
        for i, block in enumerate(down_segment.ads):
            block.pcbm = MagicMock(spec_set=['hof'])
            block.pcbm.hof = i
        deepcopy.side_effect = ['1', '2', '3']
        path_ = PathCombinator._join_down_segment(path, down_segment)
        ntools.eq_(path_.down_segment_info, down_segment.iof)
        ntools.assert_false(path_.down_segment_info.up_flag)
        ntools.eq_(path_.down_segment_hops, [first_hop, 6, '1', '2', '3'])
        deepcopy.assert_has_calls([call(0), call(1), call(2)])
        ntools.eq_(path_.down_segment_hops[0].info, OpaqueFieldType.LAST_OF)


class TestPathCombinatorJoinUpSegmentShortcuts(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_up_segment_shortcuts
    """
    def test(self):
        path = MagicMock(spec_set=['up_segment_info', 'up_segment_hops',
                                   'up_segment_upstream_ad'])
        path.up_segment_hops = [9, 10]
        up_segment = MagicMock(spec_set=['iof', 'ads'])
        up_segment.iof = MagicMock(spec_set=['info', 'hops', 'up_flag'])
        up_segment.iof.hops = 10
        up_segment.ads = [MagicMock(spec_set=['pcbm']) for i in range(6)]
        for i, block in enumerate(up_segment.ads):
            block.pcbm = MagicMock(spec_set=['hof'])
            block.pcbm.hof = i
        last_hop = up_segment.ads[3].pcbm.hof = MagicMock(spec_set=['info'])
        up_index = 3
        upstream_ad = up_segment.ads[up_index - 1].pcbm.hof = \
            MagicMock(spec_set=['info'])
        path_ = PathCombinator._join_up_segment_shortcuts(path, up_segment,
                                                          'info', up_index)
        ntools.eq_(path_.up_segment_info, up_segment.iof)
        ntools.eq_(path_.up_segment_info.info, 'info')
        ntools.eq_(path_.up_segment_info.hops, 7)
        ntools.assert_true(path_.up_segment_info.up_flag)
        ntools.eq_(path_.up_segment_hops, [9, 10, 5, 4, last_hop])
        ntools.eq_(path_.up_segment_hops[-1].info, OpaqueFieldType.LAST_OF)
        ntools.eq_(path_.up_segment_upstream_ad, upstream_ad)
        ntools.eq_(path_.up_segment_upstream_ad.info, OpaqueFieldType.NORMAL_OF)


class TestPathCombinatorJoinDownSegmentShortcuts(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_down_segment_shortcuts
    """
    def test(self):
        path = MagicMock(spec_set=['down_segment_info', 'down_segment_hops',
                                   'down_segment_upstream_ad'])
        first_hop = MagicMock(spec_set=['info'])
        path.down_segment_hops = [first_hop, 10]
        down_segment = MagicMock(spec_set=['iof', 'ads'])
        down_segment.iof = MagicMock(spec_set=['info', 'hops', 'up_flag'])
        down_segment.iof.hops = 10
        down_segment.ads = [MagicMock(spec_set=['pcbm']) for i in range(6)]
        for i, block in enumerate(down_segment.ads):
            block.pcbm = MagicMock(spec_set=['hof'])
            block.pcbm.hof = i
        dw_index = 3
        upstream_ad = down_segment.ads[dw_index - 1].pcbm.hof = \
            MagicMock(spec_set=['info'])
        path_ = PathCombinator._join_down_segment_shortcuts(path, down_segment,
                                                            'info', dw_index)
        ntools.eq_(path_.down_segment_info, down_segment.iof)
        ntools.eq_(path_.down_segment_info.info, 'info')
        ntools.eq_(path_.down_segment_info.hops, 7)
        ntools.assert_false(path_.down_segment_info.up_flag)
        ntools.eq_(path_.down_segment_upstream_ad, upstream_ad)
        ntools.eq_(path_.down_segment_upstream_ad.info,
                   OpaqueFieldType.NORMAL_OF)
        ntools.eq_(path_.down_segment_hops, [first_hop, 10, 3, 4, 5])
        ntools.eq_(path_.down_segment_hops[0].info, OpaqueFieldType.LAST_OF)


class TestPathCombinatorJoinShortcutsPeer(object):
    """
    Unit tests for lib.packet.path.PathCombinator._join_shortcuts_peer
    """
    def test(self):
        path = MagicMock(spec_set=['up_segment_peering_link',
                                   'down_segment_peering_link'])
        up_ad = MagicMock(spec_set=['pms', 'pcbm'])
        up_ad.pcbm = MagicMock(spec_set=['ad_id'])
        up_ad.pcbm.ad_id = 123
        down_ad = MagicMock(spec_set=['pms', 'pcbm'])
        down_ad.pcbm = MagicMock(spec_set=['ad_id'])
        down_ad.pcbm.ad_id = 456
        up_ad.pms = [MagicMock(spec_set=['ad_id', 'hof']) for i in range(2)]
        down_ad.pms = [MagicMock(spec_set=['ad_id', 'hof']) for i in range(3)]
        up_ad.pms[1].ad_id = 456
        up_ad.pms[1].hof = 'up_hof1'
        down_ad.pms[0].ad_id = 123
        down_ad.pms[0].hof = 'down_hof0'
        path_ = PathCombinator._join_shortcuts_peer(path, up_ad, down_ad)
        ntools.eq_(path_.up_segment_peering_link, 'up_hof1')
        ntools.eq_(path_.down_segment_peering_link, 'down_hof0')


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
