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
:mod:`lib_packet_path_mgmt_test` --- lib.packet.path_mgmt tests
=====================================================
"""
# Stdlib
import struct
from unittest.mock import patch, MagicMock

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
from lib.packet.scion import PacketType
from lib.packet.scion_addr import ISD_AD, SCIONAddr


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
        parse.assert_called_once_with(pth_seg_info, data)
        ntools.eq_(pth_seg_info.type, 0xe)
        ntools.eq_(pth_seg_info.src_isd, 0x2a0a)
        ntools.eq_(pth_seg_info.dst_isd, 0x0b0c)
        ntools.eq_(pth_seg_info.src_ad, 0x0102030405060708)
        ntools.eq_(pth_seg_info.dst_ad, 0x9192939495969798)


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
        ntools.eq_(pth_seg_info.pack(),
                   bytes.fromhex('0e 2a0a 0b0c 0102030405060708' \
                                 '9192939495969798'))


class TestPathSegmentInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.from_values
    """
    def test_basic(self):
        pth_seg_info = PathSegmentInfo.from_values(0xe, 0x2a0a, 0x0b0c,
                                                   0x0102030405060708,
                                                   0x9192939495969798)
        ntools.eq_(pth_seg_info.type, 0xe)
        ntools.eq_(pth_seg_info.src_isd, 0x2a0a)
        ntools.eq_(pth_seg_info.dst_isd, 0x0b0c)
        ntools.eq_(pth_seg_info.src_ad, 0x0102030405060708)
        ntools.eq_(pth_seg_info.dst_ad, 0x9192939495969798)
        ntools.assert_is_instance(pth_seg_info, PathSegmentInfo)


class TestPathSegmentRecordsInit(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, __init__):
        pth_seg_rec = PathSegmentRecords()
        ntools.assert_is_none(pth_seg_rec.info)
        ntools.assert_is_none(pth_seg_rec.pcbs)
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
    @patch("lib.packet.path_mgmt.PathSegmentInfo")
    def test_basic(self, pth_seg_info, deserialize, parse_payload):
        deserialize.return_value = "data1"
        pth_seg_info.return_value = "data2"
        pth_seg_info.LEN = PathSegmentInfo.LEN
        pth_seg_rec = PathSegmentRecords()
        data = b"randomstring"
        pth_seg_rec.parse(data)
        parse_payload.assert_called_once_with(pth_seg_rec, data)
        pth_seg_info.assert_called_once_with(data[:PathSegmentInfo.LEN])
        deserialize.assert_called_once_with(data[PathSegmentInfo.LEN:])
        ntools.eq_(pth_seg_rec.pcbs, "data1")
        ntools.eq_(pth_seg_rec.info, "data2")


class TestPathSegmentRecordsPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.pack
    """
    @patch("lib.packet.pcb.PathSegment.serialize")
    def test_basic(self, serialize):
        serialize.return_value = "data2"
        pth_seg_rec = PathSegmentRecords()
        pth_seg_rec.info = MagicMock(spec_set=['pack'])
        pth_seg_rec.info.pack.return_value = "data1"
        pth_seg_rec.pcbs = "data"
        ntools.eq_(pth_seg_rec.pack(), "data1"+"data2")
        pth_seg_rec.info.pack.assert_called_once_with()
        serialize.assert_called_once_with("data")


class TestPathSegmentRecordsFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.from_values
    """
    def test_basic(self):
        pth_seg_rec = PathSegmentRecords.from_values("data1", "data2")
        ntools.eq_(pth_seg_rec.info, "data1")
        ntools.eq_(pth_seg_rec.pcbs, "data2")
        ntools.assert_is_instance(pth_seg_rec, PathSegmentRecords)


class TestLeaseInfoInit(object):
    """
    Unit tests for lib.packet.path_mgmt.LeaseInfo.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, init):
        les_inf = LeaseInfo()
        ntools.eq_(les_inf.seg_type, PathSegmentType.DOWN)
        ntools.eq_(les_inf.isd_id, 0)
        ntools.eq_(les_inf.ad_id, 0)
        ntools.eq_(les_inf.exp_time, 0)
        ntools.eq_(les_inf.seg_id, b"")
        init.assert_called_once_with(les_inf)

    @patch("lib.packet.path_mgmt.LeaseInfo.parse")
    def test_raw(self, parse):
        LeaseInfo("data")
        parse.assert_called_once_with("data")


class TestLeaseInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.LeaseInfo.parse
    """
    @patch("lib.packet.packet_base.PayloadBase.parse")
    def test_basic(self, parse):
        les_inf = LeaseInfo()
        data = bytes.fromhex('0e 2a0a 0b0c 01020304') + \
            b"superlengthybigstringoflength32."
        les_inf.parse(data)
        parse.assert_called_once_with(les_inf, data)
        ntools.eq_(les_inf.seg_type, 0x0e)
        ntools.eq_(les_inf.isd_id, 0x2a0a)
        ntools.eq_(les_inf.ad_id, 0x0b0c)
        ntools.eq_(les_inf.exp_time, 0x01020304)
        ntools.eq_(les_inf.seg_id, b"superlengthybigstringoflength32.")

    @patch("lib.packet.packet_base.PayloadBase.parse")
    def test_len(self, parse):
        les_inf = LeaseInfo()
        data = bytes.fromhex('0e 2a0a 0b0c 01020304') + \
               b"superlengthybigstringoflength3"
        les_inf.parse(data)
        parse.assert_called_once_with(les_inf, data)
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
        les_inf = LeaseInfo.from_values(0x0e, 0x2a0a, 0x0b0c, 0x01020304,
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
        les_inf = LeaseInfo.from_values(0x0e, 0x2a0a, 0x0b0c, 0x01020304,
                                        b"superlengthybigstringoflength32.")
        ntools.eq_(les_inf.seg_type, 0x0e)
        ntools.eq_(les_inf.isd_id, 0x2a0a)
        ntools.eq_(les_inf.ad_id, 0x0b0c)
        ntools.eq_(les_inf.exp_time, 0x01020304)
        ntools.eq_(les_inf.seg_id, b"superlengthybigstringoflength32.")
        ntools.assert_is_instance(les_inf, LeaseInfo)


class TestPathSegmentLeases(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentLeases.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, init):
        pth_seg_les = PathSegmentLeases()
        ntools.eq_(pth_seg_les.nleases, 0)
        ntools.eq_(pth_seg_les.leases, [])
        init.assert_called_once_with(pth_seg_les)

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
            data += bytes.fromhex('0e 2a0a 0b0c 01020304') + \
                b"superlengthybigstringoflength32" + struct.pack("!B", i)
        pth_seg_les.parse(data)
        parse.assert_called()
        ntools.eq_(pth_seg_les.nleases, 0x04)
        for i in range(0x04):
            ntools.eq_(pth_seg_les.leases[i].pack(),
                       bytes.fromhex('0e 2a0a 0b0c 01020304') + \
                       b"superlengthybigstringoflength32" + \
                       struct.pack("!B", i))


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
            data += temp
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
        ntools.assert_is_instance(pth_seg_les, PathSegmentLeases)


class TestRevocationInfoInit(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, init):
        rev_inf = RevocationInfo()
        ntools.eq_(rev_inf.rev_type, RevocationType.DOWN_SEGMENT)
        ntools.eq_(rev_inf.incl_seg_id, False)
        ntools.eq_(rev_inf.incl_hop, False)
        ntools.eq_(rev_inf.seg_id, b"")
        ntools.eq_(rev_inf.rev_token1, b"")
        ntools.eq_(rev_inf.proof1, b"")
        ntools.eq_(rev_inf.rev_token2, b"")
        ntools.eq_(rev_inf.proof2, b"")
        init.assert_called_once_with(rev_inf)

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
        data = struct.pack("!B", 0b00000101) + \
            b"superlengthybigstringoflength321" + \
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
        ntools.assert_true(rev_inf.parsed)
        ntools.eq_(rev_inf.raw, data)

    def test_var_size(self):
        rev_inf = RevocationInfo()
        data = struct.pack("!B", 0b00011011) + \
            b"superlengthybigstringoflength321" + \
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
        ntools.eq_(rev_inf.raw, data)
        ntools.assert_true(rev_inf.parsed)

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
        data = struct.pack("!B", 0b00011011) + \
            b"superlengthybigstringoflength321" + \
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
        data = struct.pack("!B", 0b00000101) + \
            b"superlengthybigstringoflength321" + \
            b"superlengthybigstringoflength322"
        ntools.eq_(rev_inf.pack(), data)


class TestRevocationInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.from_values
    """
    def test_basic(self):
        rev_inf = RevocationInfo.from_values("data1", "data2", "data3", "data4",
                                             "data5", "data6", "data7", "data8")
        ntools.eq_(rev_inf.rev_type, "data1")
        ntools.eq_(rev_inf.rev_token1, "data2")
        ntools.eq_(rev_inf.proof1, "data3")
        ntools.eq_(rev_inf.incl_seg_id, "data4")
        ntools.eq_(rev_inf.seg_id, "data5")
        ntools.eq_(rev_inf.incl_hop, "data6")
        ntools.eq_(rev_inf.rev_token2, "data7")
        ntools.eq_(rev_inf.proof2, "data8")
        ntools.assert_is_instance(rev_inf, RevocationInfo)

    def test_less_arg(self):
        rev_inf = RevocationInfo.from_values("data1", "data2", "data3")
        ntools.eq_(rev_inf.rev_type, "data1")
        ntools.eq_(rev_inf.rev_token1, "data2")
        ntools.eq_(rev_inf.proof1, "data3")
        ntools.eq_(rev_inf.incl_seg_id, False)
        ntools.eq_(rev_inf.seg_id, b"")
        ntools.eq_(rev_inf.incl_hop, False)
        ntools.eq_(rev_inf.rev_token2, b"")
        ntools.eq_(rev_inf.proof2, b"")


class TestRevocationPayloadInit(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationPayload.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__")
    def test_basic(self, init):
        rev_pld = RevocationPayload()
        ntools.eq_(rev_pld.rev_infos, [])
        init.assert_called_once_with(rev_pld)

    @patch("lib.packet.path_mgmt.RevocationPayload.parse")
    def test_raw(self, parse):
        RevocationPayload("data")
        parse.assert_called_once_with("data")


class TestRevocationPayloadParse(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationPayload.parse
    """
    @patch("lib.packet.packet_base.PayloadBase.parse")
    def test_basic(self, parse):
        rev_pld = RevocationPayload()
        data = b""
        for i in range(0x04):
            data += struct.pack("!B", 0b00011011) + \
                b"superlengthybigstringoflength321" + \
                b"superlengthybigstringoflength322" + \
                b"superlengthybigstringoflength323" + \
                b"superlengthybigstringoflength324" + \
                b"superlengthybigstringoflength32" + struct.pack("!B", i)
        rev_pld.parse(data)
        parse.assert_called_once_with(rev_pld, data)
        for i in range(0x04):
            temp = struct.pack("!B", 0b00011011) + \
                b"superlengthybigstringoflength321" + \
                b"superlengthybigstringoflength322" + \
                b"superlengthybigstringoflength323" + \
                b"superlengthybigstringoflength324" + \
                b"superlengthybigstringoflength32" + struct.pack("!B", i)
            ntools.eq_(rev_pld.rev_infos[i].pack(), temp)

    @patch("lib.packet.packet_base.PayloadBase.parse")
    def test_len(self, parse):
        rev_pld = RevocationPayload()
        rev_pld.parse("smalldata")
        ntools.eq_(rev_pld.rev_infos, [])


class TestRevocationPayloadPack(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationPayload.pack
    """
    def test_basic(self):
        rev_pld = RevocationPayload()
        data = b""
        for i in range(0x04):
            temp = struct.pack("!B", 0b00011011) + \
                b"superlengthybigstringoflength321" + \
                b"superlengthybigstringoflength322" + \
                b"superlengthybigstringoflength323" + \
                b"superlengthybigstringoflength324" + \
                b"superlengthybigstringoflength32" + struct.pack("!B", i)
            rinfo = RevocationInfo(temp)
            data += temp
            rev_pld.rev_infos.append(rinfo)
        ntools.eq_(rev_pld.pack(), data)


class TestRevocationPayloadFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationPayload.from_values
    """
    def test_basic(self):
        rev_pld = RevocationPayload.from_values("data")
        ntools.eq_(rev_pld.rev_infos, "data")
        ntools.assert_is_instance(rev_pld, RevocationPayload)


class TestRevocationPayloadAddRevInfo(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationPayload.add_rev_info
    """
    def test_basic(self):
        rev_pld = RevocationPayload()
        rev_inf = RevocationInfo()
        rev_pld.rev_infos = MagicMock(spec_set=['append'])
        rev_pld.add_rev_info(rev_inf)
        rev_pld.rev_infos.append.assert_called_once_with(rev_inf)


class TestPathMgmtPacketInit(object):
    """
    Unit tests for lib.packet.path_mgmt.PathMgmtPacket.__init__
    """
    @patch("lib.packet.scion.SCIONPacket.__init__")
    def test_basic(self, init):
        pth_mgmt_pkt = PathMgmtPacket()
        ntools.eq_(pth_mgmt_pkt.type, 0)
        init.assert_called_once_with(pth_mgmt_pkt)

    @patch("lib.packet.path_mgmt.PathMgmtPacket.parse")
    def test_raw(self, parse):
        PathMgmtPacket("data")
        parse.assert_called_once_with("data")


class TestPathMgmtPacketParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathMgmtPacket.parse
    """
    @patch("lib.packet.scion.SCIONPacket.set_payload")
    @patch("lib.packet.path_mgmt.PathSegmentInfo")
    @patch("lib.packet.scion.SCIONPacket.parse")
    def test_request(self, parse, inf, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", PathMgmtType.REQUEST) + \
            b"data1"
        inf.return_value = "data2"
        pth_mgmt_pkt.parse("data3")
        parse.assert_called_once_with(pth_mgmt_pkt, "data3")
        ntools.eq_(pth_mgmt_pkt.type, PathMgmtType.REQUEST)
        inf.assert_called_once_with(b"data1")
        set_pld.assert_called_once_with("data2")

    @patch("lib.packet.scion.SCIONPacket.set_payload")
    @patch("lib.packet.path_mgmt.PathSegmentRecords")
    @patch("lib.packet.scion.SCIONPacket.parse")
    def test_records(self, parse, rec, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", PathMgmtType.RECORDS) + \
            b"data1"
        rec.return_value = "data2"
        pth_mgmt_pkt.parse("data3")
        parse.assert_called_once_with(pth_mgmt_pkt, "data3")
        ntools.eq_(pth_mgmt_pkt.type, PathMgmtType.RECORDS)
        rec.assert_called_once_with(b"data1")
        set_pld.assert_called_once_with("data2")

    @patch("lib.packet.scion.SCIONPacket.set_payload")
    @patch("lib.packet.path_mgmt.PathSegmentLeases")
    @patch("lib.packet.scion.SCIONPacket.parse")
    def test_leases(self, parse, les, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", PathMgmtType.LEASES) + \
            b"data1"
        les.return_value = "data2"
        pth_mgmt_pkt.parse("data3")
        parse.assert_called_once_with(pth_mgmt_pkt, "data3")
        ntools.eq_(pth_mgmt_pkt.type, PathMgmtType.LEASES)
        les.assert_called_once_with(b"data1")
        set_pld.assert_called_once_with("data2")

    @patch("lib.packet.scion.SCIONPacket.set_payload")
    @patch("lib.packet.path_mgmt.RevocationPayload")
    @patch("lib.packet.scion.SCIONPacket.parse")
    def test_revocation(self, parse, rev, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", PathMgmtType.REVOCATIONS) + \
            b"data1"
        rev.return_value = "data2"
        pth_mgmt_pkt.parse("data3")
        parse.assert_called_once_with(pth_mgmt_pkt, "data3")
        ntools.eq_(pth_mgmt_pkt.type, PathMgmtType.REVOCATIONS)
        rev.assert_called_once_with(b"data1")
        set_pld.assert_called_once_with("data2")

    @patch("lib.packet.scion.SCIONPacket.parse")
    def test_invalid_type(self, parse):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", 5)
        pth_mgmt_pkt.parse("data")
        parse.assert_called_once_with(pth_mgmt_pkt, "data")
        ntools.eq_(pth_mgmt_pkt.type, 5)
        ntools.eq_(pth_mgmt_pkt.payload, struct.pack("!B", 5))


class TestPathMgmtPacketPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathMgmtPacket.pack
    """
    @patch("lib.packet.scion.SCIONPacket.set_payload")
    @patch("lib.packet.scion.SCIONPacket.pack")
    def test_basic(self, pack_scion, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt.type = 3
        pack_scion.return_value = "data1"
        pth_mgmt_pkt._payload = MagicMock(spec_set=['pack'])
        pth_mgmt_pkt.payload.pack.return_value = b"data2"
        ntools.eq_(pth_mgmt_pkt.pack(), "data1")
        pth_mgmt_pkt.payload.pack.assert_called_once_with()
        set_pld.assert_called_once_with(struct.pack("!B", 3) + b"data2")
        pack_scion.assert_called_once_with(pth_mgmt_pkt)

    @patch("lib.packet.scion.SCIONPacket.pack")
    def test_bytes(self, pack_scion):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = b"data1"
        pack_scion.return_value = "data2"
        ntools.eq_(pth_mgmt_pkt.pack(), "data2")
        pack_scion.assert_called_once_with(pth_mgmt_pkt)


class TestPathMgmtPacketFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathMgmtPacket.from_values
    """
    @patch("lib.packet.scion.SCIONPacket.set_payload")
    @patch("lib.packet.packet_base.PacketBase.set_hdr")
    @patch("lib.packet.scion.SCIONHeader.from_values")
    @patch("lib.packet.scion_addr.SCIONAddr.from_values")
    def test_basic(self, from_values, from_values_hdr, set_hdr, set_pld):
        src_addr = ISD_AD("data1", "data2")
        dst_addr = SCIONAddr()
        from_values.return_value = "data3"
        from_values_hdr.return_value = "data4"
        pth_mgmt_pkt = PathMgmtPacket.from_values("data5", "data6", "data7",
                                                  src_addr, dst_addr)
        from_values.assert_called_once_with("data1", "data2",
                                            PacketType.PATH_MGMT)
        from_values_hdr.assert_called_once_with("data3", dst_addr, "data7")
        set_hdr.assert_called_once_with("data4")
        ntools.eq_(pth_mgmt_pkt.type, "data5")
        set_pld.assert_called_once_with("data6")
        ntools.assert_is_instance(pth_mgmt_pkt, PathMgmtPacket)

    @patch("lib.packet.scion.SCIONPacket.set_payload")
    @patch("lib.packet.packet_base.PacketBase.set_hdr")
    @patch("lib.packet.scion.SCIONHeader.from_values")
    @patch("lib.packet.scion_addr.SCIONAddr.from_values")
    def test_basic2(self, from_values, from_values_hdr, set_hdr, set_pld):
        src_addr = SCIONAddr()
        dst_addr = ISD_AD("data1", "data2")
        from_values.return_value = "data3"
        from_values_hdr.return_value = "data4"
        pth_mgmt_pkt = PathMgmtPacket.from_values("data5", "data6", "data7",
                                                  src_addr, dst_addr)
        from_values.assert_called_once_with("data1", "data2",
                                            PacketType.PATH_MGMT)
        from_values_hdr.assert_called_once_with(src_addr, "data3", "data7")
        set_hdr.assert_called_once_with("data4")
        ntools.eq_(pth_mgmt_pkt.type, "data5")
        set_pld.assert_called_once_with("data6")

    @patch("lib.packet.scion.SCIONPacket.set_payload")
    @patch("lib.packet.packet_base.PacketBase.set_hdr")
    @patch("lib.packet.scion.SCIONHeader.from_values")
    def test_invalid(self, from_values, set_hdr, set_pld):
        from_values.return_value = "data6"
        pth_mgmt_pkt = PathMgmtPacket.from_values("data1", "data2", "data3",
                                                  "data4", "data5")
        from_values.assert_called_once_with("data4", "data5", "data3")
        set_hdr.assert_called_once_with("data6")
        ntools.eq_(pth_mgmt_pkt.type, "data1")
        set_pld.assert_called_once_with("data2")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
