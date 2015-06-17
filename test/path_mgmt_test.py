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
:mod:`path_mgmt_test` --- SCION path management tests
=====================================================
"""
# Stdlib
import struct
from unittest.mock import MagicMock, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.path_mgmt import (
    LeaseInfo,
    PathMgmtPacket,
    PathMgmtType,
    PathSegmentInfo,
    PathSegmentLeases,
    PathSegmentRecords,
    PathSegmentType,
    RevocationInfo,
    RevocationPayload,
    RevocationType
)
from lib.packet.packet_base import PayloadBase


class TestPathSegmentInfoInit(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, __init__):
        pth_seg_info = PathSegmentInfo()
        ntools.eq_(pth_seg_info.type, 0)
        ntools.eq_(pth_seg_info.src_isd, 0)
        ntools.eq_(pth_seg_info.dst_isd, 0)
        ntools.eq_(pth_seg_info.src_ad, 0)
        ntools.eq_(pth_seg_info.dst_ad, 0)
        __init__.assert_called_once_with(pth_seg_info)

    @patch("lib.packet.path_mgmt.PathSegmentInfo.parse")
    def test_raw(self, parse):
        PathSegmentInfo("data")
        parse.assert_called_once_with("data")


class TestPathSegmentInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.parse
    """
    @patch("lib.packet.packet_base.PayloadBase.parse")
    def test_basic(self, parse):
        pth_seg_info = PathSegmentInfo()
        data = bytes.fromhex('0e 2a0a 0b0c 0102030405060708 9192939495969798')
        pth_seg_info.parse(data)
        ntools.eq_(pth_seg_info.type, 0xe)
        ntools.eq_(pth_seg_info.src_isd, 0x2a0a)
        ntools.eq_(pth_seg_info.dst_isd, 0x0b0c)
        ntools.eq_(pth_seg_info.src_ad, 0x0102030405060708)
        ntools.eq_(pth_seg_info.dst_ad, 0x9192939495969798)
        parse.assert_called_once_with(pth_seg_info, data)


class TestPathSegmentInfoPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.pack
    """
    def test_basic(self):
        pth_seg_info = PathSegmentInfo()
        pth_seg_info.type = 0xe
        pth_seg_info.src_isd = 0x2a0a
        pth_seg_info.dst_isd = 0x0b0c
        pth_seg_info.src_ad = 0x0102030405060708
        pth_seg_info.dst_ad = 0x9192939495969798
        ntools.eq_(pth_seg_info.pack(), bytes.fromhex('0e 2a0a 0b0c 0102030405060708 9192939495969798'))


class TestPathSegmentInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.from_values
    """
    def test_basic(self):
        pth_seg_info = PathSegmentInfo.from_values(0xe, 0x2a0a, 0x0b0c, 0x0102030405060708, 0x9192939495969798)
        ntools.eq_(pth_seg_info.type, 0xe)
        ntools.eq_(pth_seg_info.src_isd, 0x2a0a)
        ntools.eq_(pth_seg_info.dst_isd, 0x0b0c)
        ntools.eq_(pth_seg_info.src_ad, 0x0102030405060708)
        ntools.eq_(pth_seg_info.dst_ad, 0x9192939495969798)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
