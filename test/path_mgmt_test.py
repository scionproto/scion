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
        ntools.eq_(pth_seg_info.pack(), bytes.fromhex('0e 2a0a 0b0c'  \
                                                      '0102030405060708' \
                                                      '9192939495969798'))


class TestPathSegmentInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.from_values
    """
    def test_basic(self):
        pth_seg_info = PathSegmentInfo.from_values(0xe, 0x2a0a, 0x0b0c, \
                                                   0x0102030405060708, \
                                                   0x9192939495969798)
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
        deserialize.return_value = "data1"
        parse_payload.return_value = "data2"
        pth_seg_rec = PathSegmentRecords()
        data = "randomstring"
        pth_seg_rec.parse(data)
        parse_payload.assert_called_once_with(pth_seg_rec, data)
        deserialize.assert_called_once_with(data[PathSegmentInfo.LEN:])
        parse.assert_called_once_with(data[:PathSegmentInfo.LEN])
        pth_seg_rec.info = "data1"
        pth_seg_rec.pcbs = "data2"


class TestPathSegmentRecordsPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.pack
    """
    @patch("lib.packet.pcb.PathSegment.serialize")
    @patch("lib.packet.path_mgmt.PathSegmentInfo.pack")
    def test_basic(self, pack, serialize):
        pack.return_value = "data1"
        serialize.return_value = "data2"
        pth_seg_rec = PathSegmentRecords()
        pth_seg_rec.info = PathSegmentInfo()
        pth_seg_rec.pcbs = "data"
        ntools.eq_(pth_seg_rec.pack(), "data1"+"data2")
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
        data = bytes.fromhex('0e 2a0a 0b0c 01020304') + \
               b"superlengthybigstringoflength32."
        les_inf.parse(data)
        ntools.eq_(les_inf.seg_type, 0x0e)
        ntools.eq_(les_inf.isd_id, 0x2a0a)
        ntools.eq_(les_inf.ad_id, 0x0b0c)
        ntools.eq_(les_inf.exp_time, 0x01020304)
        ntools.eq_(les_inf.seg_id, b"superlengthybigstringoflength32.")

    def test_len(self):
        les_inf = LeaseInfo()
        data = bytes.fromhex('0e 2a0a 0b0c 01020304') + \
               b"superlengthybigstringoflength3"
        les_inf.parse(data)
        ntools.eq_(les_inf.seg_type, PathSegmentType.DOWN)
        ntools.eq_(les_inf.isd_id, 0)
        ntools.eq_(les_inf.ad_id, 0)
        ntools.eq_(les_inf.exp_time, 0)
        ntools.eq_(les_inf.seg_id, b"")


class TestLeaseInfoPack(object):
    """
    Unit tests for lib.packet.path_mgmt.LeaseInfo.from_values
    """
    def test_basic(self):
        les_inf = LeaseInfo.from_values(0x0e, 0x2a0a, 0x0b0c, 0x01020304, \
                                        b"superlengthybigstringoflength32.")
        ntools.eq_(les_inf.seg_type, 0x0e)
        ntools.eq_(les_inf.isd_id, 0x2a0a)
        ntools.eq_(les_inf.ad_id, 0x0b0c)
        ntools.eq_(les_inf.exp_time, 0x01020304)
        ntools.eq_(les_inf.seg_id, b"superlengthybigstringoflength32.")


class TestLeaseInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.LeaseInfo.from_values
    """
    def test_basic(self):
        les_inf = LeaseInfo.from_values(0x0e, 0x2a0a, 0x0b0c, 0x01020304, \
                                        b"superlengthybigstringoflength32.")
        ntools.eq_(les_inf.seg_type, 0x0e)
        ntools.eq_(les_inf.isd_id, 0x2a0a)
        ntools.eq_(les_inf.ad_id, 0x0b0c)
        ntools.eq_(les_inf.exp_time, 0x01020304)
        ntools.eq_(les_inf.seg_id, b"superlengthybigstringoflength32.")


class TestPathSegmentLeases(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentLeases.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, __init__):
        pth_seg_les = PathSegmentLeases()
        ntools.eq_(pth_seg_les.nleases, 0)
        ntools.eq_(pth_seg_les.leases, [])
        __init__.assert_called_once_with(pth_seg_les)

    @patch("lib.packet.path_mgmt.PathSegmentLeases.parse")
    def test_raw(self, parse):
        PathSegmentLeases("data")
        parse.assert_called_once_with("data")


class TestPathSegmentLeasesParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentLeases.parse
    """
    @patch("lib.packet.packet_base.PayloadBase.parse")
    def test_basic(self, parse):
        pth_seg_les = PathSegmentLeases()
        data = bytes.fromhex('04')
        for i in range(0x04):
            data = data + bytes.fromhex('0e 2a0a 0b0c 01020304') + \
                   b"superlengthybigstringoflength32" + struct.pack("!B", i)
        pth_seg_les.parse(data)
        parse.assert_called()
        ntools.eq_(pth_seg_les.nleases, 0x04)
        for i in range(0x04):
            ntools.eq_(pth_seg_les.leases[i].pack(), \
                       bytes.fromhex('0e 2a0a 0b0c 01020304') + \
                       b"superlengthybigstringoflength32" + struct.pack("!B", i))


class TestPathSegmentLeasesPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentLeases.pack
    """
    def test_basic(self):
        pth_seg_les = PathSegmentLeases()
        pth_seg_les.nleases = 0x04
        data = bytes.fromhex('04')
        for i in range(0x04):
            temp = bytes.fromhex('0e 2a0a 0b0c 01020304') + \
                   b"superlengthybigstringoflength32" + struct.pack("!B", i)
            linfo = LeaseInfo(temp)
            data = data + temp
            pth_seg_les.leases.append(linfo)
        ntools.eq_(pth_seg_les.pack(), data)


class TestPathSegmentLeasesFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentLeases.from_values
    """
    def test_basic(self):
        pth_seg_les = PathSegmentLeases.from_values(4, "data")
        ntools.eq_(pth_seg_les.nleases, 4)
        ntools.eq_(pth_seg_les.leases, "data")


class TestRevocationInfoInit(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, __init__):
        rev_inf = RevocationInfo()
        ntools.eq_(rev_inf.rev_type, RevocationType.DOWN_SEGMENT)
        ntools.eq_(rev_inf.incl_seg_id, False)
        ntools.eq_(rev_inf.incl_hop, False)
        ntools.eq_(rev_inf.seg_id, b"")
        ntools.eq_(rev_inf.rev_token1, b"")
        ntools.eq_(rev_inf.proof1, b"")
        ntools.eq_(rev_inf.rev_token2, b"")
        ntools.eq_(rev_inf.proof2, b"")
        __init__.assert_called_once_with(rev_inf)

    @patch("lib.packet.path_mgmt.RevocationInfo.parse")
    def test_raw(self, parse):
        RevocationInfo("data")
        parse.assert_called_once_with("data")


class TestRevocationInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.parse
    """
    def test_basic(self):
        rev_inf = RevocationInfo()
        data = struct.pack("!B", 0b00000101) + b"superlengthybigstringoflength321" + \
               b"superlengthybigstringoflength322"
        rev_inf.parse(data)
        ntools.eq_(rev_inf.rev_type, 0b00000101 & 0x7)
        ntools.eq_(rev_inf.incl_seg_id, (0b00000101 >> 3) & 0x1)
        ntools.eq_(rev_inf.incl_hop, (0b00000101 >> 4) & 0x1)
        ntools.eq_(rev_inf.seg_id, b"")
        ntools.eq_(rev_inf.rev_token1, b"superlengthybigstringoflength321")
        ntools.eq_(rev_inf.proof1, b"superlengthybigstringoflength322")
        ntools.eq_(rev_inf.rev_token2, b"")
        ntools.eq_(rev_inf.proof2, b"")

    def test_var_size(self):
        rev_inf = RevocationInfo()
        data = struct.pack("!B", 0b00011011) + b"superlengthybigstringoflength321" + \
               b"superlengthybigstringoflength322" + \
               b"superlengthybigstringoflength323" + \
               b"superlengthybigstringoflength324" + \
               b"superlengthybigstringoflength325"
        rev_inf.parse(data)
        ntools.eq_(rev_inf.rev_type, 0b00011011 & 0x7)
        ntools.eq_(rev_inf.incl_seg_id, (0b00011011 >> 3) & 0x1)
        ntools.eq_(rev_inf.incl_hop, (0b00011011 >> 4) & 0x1)
        ntools.eq_(rev_inf.seg_id, b"superlengthybigstringoflength321")
        ntools.eq_(rev_inf.rev_token1, b"superlengthybigstringoflength322")
        ntools.eq_(rev_inf.proof1, b"superlengthybigstringoflength323")
        ntools.eq_(rev_inf.rev_token2, b"superlengthybigstringoflength324")
        ntools.eq_(rev_inf.proof2, b"superlengthybigstringoflength325")

    def test_len(self):
        rev_inf = RevocationInfo()
        data = b"randomshortstring"
        rev_inf.parse(data)
        ntools.eq_(rev_inf.rev_type, RevocationType.DOWN_SEGMENT)
        ntools.eq_(rev_inf.incl_seg_id, False)
        ntools.eq_(rev_inf.incl_hop, False)
        ntools.eq_(rev_inf.seg_id, b"")
        ntools.eq_(rev_inf.rev_token1, b"")
        ntools.eq_(rev_inf.proof1, b"")
        ntools.eq_(rev_inf.rev_token2, b"")
        ntools.eq_(rev_inf.proof2, b"")


class TestRevocationInfoPack(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.from_values
    """
    def test_basic(self):
        rev_inf = RevocationInfo()
        rev_inf.rev_type = 0b00011011 & 0x7
        rev_inf.incl_seg_id = (0b00011011 >> 3) & 0x1
        rev_inf.incl_hop = (0b00011011 >> 4) & 0x1
        rev_inf.seg_id = b"superlengthybigstringoflength321"
        rev_inf.rev_token1 = b"superlengthybigstringoflength322"
        rev_inf.proof1 = b"superlengthybigstringoflength323"
        rev_inf.rev_token2 = b"superlengthybigstringoflength324"
        rev_inf.proof2 = b"superlengthybigstringoflength325"
        data = struct.pack("!B", 0b00011011) + b"superlengthybigstringoflength321" + \
               b"superlengthybigstringoflength322" + \
               b"superlengthybigstringoflength323" + \
               b"superlengthybigstringoflength324" + \
               b"superlengthybigstringoflength325"
        ntools.eq_(rev_inf.pack(), data)

    def test_var_size(self):
        rev_inf = RevocationInfo()
        rev_inf.rev_type = 0b00000101 & 0x7
        rev_inf.incl_seg_id = (0b00000101 >> 3) & 0x1
        rev_inf.incl_hop = (0b00000101 >> 4) & 0x1
        rev_inf.rev_token1 = b"superlengthybigstringoflength321"
        rev_inf.proof1 = b"superlengthybigstringoflength322"
        data = struct.pack("!B", 0b00000101) + b"superlengthybigstringoflength321" + \
               b"superlengthybigstringoflength322"
        ntools.eq_(rev_inf.pack(), data)


class TestRevocationInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.from_values
    """
    def test_basic(self):
        rev_inf = RevocationInfo.from_values("data1", "data2", "data3", "data4", \
                                             "data5", "data6", "data7", "data8")
        ntools.eq_(rev_inf.rev_type, "data1")
        ntools.eq_(rev_inf.rev_token1, "data2")
        ntools.eq_(rev_inf.proof1, "data3")
        ntools.eq_(rev_inf.incl_seg_id, "data4")
        ntools.eq_(rev_inf.incl_hop, "data6")
        ntools.eq_(rev_inf.seg_id, "data5")
        ntools.eq_(rev_inf.rev_token2, "data7")
        ntools.eq_(rev_inf.proof2, "data8")

    def test_less_arg(self):
        rev_inf = RevocationInfo.from_values("data1", "data2", "data3")
        ntools.eq_(rev_inf.rev_type, "data1")
        ntools.eq_(rev_inf.rev_token1, "data2")
        ntools.eq_(rev_inf.proof1, "data3")
        ntools.eq_(rev_inf.incl_seg_id, False)
        ntools.eq_(rev_inf.incl_hop, False)
        ntools.eq_(rev_inf.seg_id, b"")
        ntools.eq_(rev_inf.rev_token2, b"")
        ntools.eq_(rev_inf.proof2, b"")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
