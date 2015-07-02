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
    PeerPath,
)
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
)


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


class TestPathBaseGetFirstHopOf(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.get_first_hop_of
    """
    def test_with_up_hops(self):
        self.path.down_segment_hops = self.hof[2:5]
        self.path.up_segment_hops = self.hof[:3]
        ntools.eq_(self.path.get_first_hop_of(), self.hof[0])

    def test_with_down_hops(self):
        self.path.down_segment_hops = self.hof[2:5]
        ntools.eq_(self.path.get_first_hop_of(), self.hof[2])

    def test_without_hops(self):
        ntools.eq_(self.path.get_first_hop_of(), None)


class TestPathBaseGetOf(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.get_of
    """
    def _check(self, idx, val):
        self.path.up_segment_info = self.iof[0]
        self.path.down_segment_info = self.iof[1]
        self.path.down_segment_hops = self.hof[2:5]
        self.path.up_segment_hops = self.hof[:3]
        ntools.eq_(self.path.get_of(idx), val)

    def test(self):
        for i, v in enumerate([self.iof[0]] + self.hof[:3] + [self.iof[1]] +
                              self.hof[2:5] + [None]):
            yield self._check, i, v


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


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
