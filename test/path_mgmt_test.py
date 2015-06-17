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
from unittest.mock import patch

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
from lib.packet.pcb import PathSegment


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


class TestPathSegmentRecordsInit(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, __init__):
        pth_seg_rec = PathSegmentRecords()
        ntools.assert_true(pth_seg_rec.info is None)
        ntools.assert_true(pth_seg_rec.pcbs is None)
        __init__.assert_called_once_with(pth_seg_rec)

    @patch("lib.packet.path_mgmt.PathSegmentRecords.parse")
    def test_raw(self, parse):
        PathSegmentRecords("data")
        parse.assert_called_once_with("data")


class TestPathSegmentRecordsParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.parse
    """
    @patch("lib.packet.packet_base.PayloadBase.parse")
    @patch("lib.packet.pcb.PathSegment.deserialize")
    @patch("lib.packet.path_mgmt.PathSegmentInfo.parse")
    def test_basic(self, parse, deserialize, parse_payload):
        pth_seg_rec = PathSegmentRecords()
        data = "randomstring"
        pth_seg_rec.parse(data)
        parse_payload.assert_called_once_with(pth_seg_rec, data)
        deserialize.assert_called_with(data[PathSegmentInfo.LEN:])
        parse.assert_called_once_with(data[:PathSegmentInfo.LEN])


class TestPathSegmentRecordsPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.pack
    """
    @patch("lib.packet.pcb.PathSegment.serialize")
    @patch("lib.packet.path_mgmt.PathSegmentInfo.pack")
    def test_basic(self, pack, serialize):
        pth_seg_rec = PathSegmentRecords()
        pth_seg_rec.info = PathSegmentInfo()
        pth_seg_rec.pcbs = "data"
        pth_seg_rec.pack()
        serialize.assert_called_once_with("data")
        pack.assert_called_with()


class TestPathSegmentRecordsFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.from_values
    """
    def test_basic(self):
        pth_seg_rec = PathSegmentRecords.from_values("data1", "data2")
        ntools.eq_(pth_seg_rec.info, "data1")
        ntools.eq_(pth_seg_rec.pcbs, "data2")
        

class TestLeaseInfoInit(object):
    """
    Unit tests for lib.packet.path_mgmt.LeaseInfo.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, __init__):
        les_inf = LeaseInfo()
        ntools.eq_(les_inf.seg_type, PathSegmentType.DOWN)
        ntools.eq_(les_inf.isd_id, 0)
        ntools.eq_(les_inf.ad_id, 0)
        ntools.eq_(les_inf.exp_time, 0)
        ntools.eq_(les_inf.seg_id, b"")
        __init__.assert_called_once_with(les_inf)

    @patch("lib.packet.path_mgmt.LeaseInfo.parse")
    def test_raw(self, parse):
        LeaseInfo("data")
        parse.assert_called_once_with("data")


class TestLeaseInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.LeaseInfo.parse
    """
    def test_basic(self):
        les_inf = LeaseInfo()
        data = bytes.fromhex('0e 2a0a 0b0c 01020304') + b"superlengthybigstringoflength32."
        les_inf.parse(data)
        ntools.eq_(les_inf.seg_type, 0x0e)
        ntools.eq_(les_inf.isd_id, 0x2a0a)
        ntools.eq_(les_inf.ad_id, 0x0b0c)
        ntools.eq_(les_inf.exp_time, 0x01020304)
        ntools.eq_(les_inf.seg_id, b"superlengthybigstringoflength32.")
    
    def test_len(self):
        les_inf = LeaseInfo()
        data = bytes.fromhex('0e 2a0a 0b0c 01020304') + b"superlengthybigstringoflength3"
        ntools.eq_(les_inf.seg_type, PathSegmentType.DOWN)
        ntools.eq_(les_inf.isd_id, 0)
        ntools.eq_(les_inf.ad_id, 0)
        ntools.eq_(les_inf.exp_time, 0)
        ntools.eq_(les_inf.seg_id, b"")

class TestLeaseInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.LeaseInfo.from_values
    """
    def test_basic(self):
        les_inf = LeaseInfo.from_values(0x0e, 0x2a0a, 0x0b0c, 0x01020304, b"superlengthybigstringoflength32.")
        ntools.eq_(les_inf.seg_type, 0x0e)
        ntools.eq_(les_inf.isd_id, 0x2a0a)
        ntools.eq_(les_inf.ad_id, 0x0b0c)
        ntools.eq_(les_inf.exp_time, 0x01020304)
        ntools.eq_(les_inf.seg_id, b"superlengthybigstringoflength32.")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
