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
from unittest.mock import patch, MagicMock, call

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
    @patch("lib.packet.packet_base.PayloadBase.__init__", autospec=True)
    def test_basic(self, init):
        pth_seg_info = PathSegmentInfo()
        ntools.eq_(pth_seg_info.type, 0)
        ntools.eq_(pth_seg_info.src_isd, 0)
        ntools.eq_(pth_seg_info.dst_isd, 0)
        ntools.eq_(pth_seg_info.src_ad, 0)
        ntools.eq_(pth_seg_info.dst_ad, 0)
        init.assert_called_once_with(pth_seg_info)

    @patch("lib.packet.path_mgmt.PathSegmentInfo.parse", autospec=True)
    def test_raw(self, parse):
        pth_seg_info = PathSegmentInfo("data")
        parse.assert_called_once_with(pth_seg_info, "data")


class TestPathSegmentInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.parse
    """
    @patch("lib.packet.path_mgmt.ISD_AD.from_raw", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.packet_base.PayloadBase.parse", autospec=True)
    def test_basic(self, parse, isd_ad):
        pth_seg_info = PathSegmentInfo()
        data = bytes.fromhex('0e 0bc0021d 021004c6')
        isd_ad.side_effect = [(0x0bc, 0x0021d), (0x021, 0x004c6)]
        pth_seg_info.parse(data)
        parse.assert_called_once_with(pth_seg_info, data)
        ntools.eq_(pth_seg_info.type, 0x0e)
        ntools.eq_(pth_seg_info.src_isd, 0x0bc)
        ntools.eq_(pth_seg_info.src_ad,  0x0021d)
        ntools.eq_(pth_seg_info.dst_isd, 0x021)
        ntools.eq_(pth_seg_info.dst_ad, 0x004c6)
        calls = [call(data[1:1 + ISD_AD.LEN]),
                 call(data[1 + ISD_AD.LEN: 1 + 2 * ISD_AD.LEN])]
        isd_ad.assert_has_calls(calls)


class TestPathSegmentInfoPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.pack
    """
    @patch("lib.packet.path_mgmt.ISD_AD", autospec=True)
    def test_basic(self, isd_ad):
        pth_seg_info = PathSegmentInfo()
        pth_seg_info.type = 0x0e
        pth_seg_info.src_isd = 0x0bc
        pth_seg_info.src_ad = 0x0021d
        pth_seg_info.dst_isd = 0x021
        pth_seg_info.dst_ad = 0x004c6
        isd_ads = [MagicMock(spec_set=['pack']), MagicMock(spec_set=['pack'])]
        isd_ads[0].pack.return_value = bytes.fromhex('0bc0021d')
        isd_ads[1].pack.return_value = bytes.fromhex('021004c6')
        isd_ad.side_effect = isd_ads
        ntools.eq_(pth_seg_info.pack(), bytes.fromhex('0e 0bc0021d 021004c6'))
        isd_ad.assert_has_calls([call(0x0bc, 0x0021d), call(0x021, 0x004c6)])
        isd_ads[0].pack.assert_called_once_with()
        isd_ads[1].pack.assert_called_once_with()


class TestPathSegmentInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.from_values
    """
    def test_basic(self):
        pth_seg_info = PathSegmentInfo.from_values(0x0e, 0x2a0a, 0x0b0c,
                                                   0x0102030405060708,
                                                   0x9192939495969798)
        ntools.eq_(pth_seg_info.type, 0x0e)
        ntools.eq_(pth_seg_info.src_isd, 0x2a0a)
        ntools.eq_(pth_seg_info.dst_isd, 0x0b0c)
        ntools.eq_(pth_seg_info.src_ad, 0x0102030405060708)
        ntools.eq_(pth_seg_info.dst_ad, 0x9192939495969798)
        ntools.assert_is_instance(pth_seg_info, PathSegmentInfo)


class TestPathSegmentRecordsInit(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__", autospec=True)
    def test_basic(self, init):
        pth_seg_rec = PathSegmentRecords()
        ntools.assert_is_none(pth_seg_rec.info)
        ntools.assert_is_none(pth_seg_rec.pcbs)
        init.assert_called_once_with(pth_seg_rec)

    @patch("lib.packet.path_mgmt.PathSegmentRecords.parse", autospec=True)
    def test_raw(self, parse):
        pth_seg_rec = PathSegmentRecords("data")
        parse.assert_called_once_with(pth_seg_rec, "data")


class TestPathSegmentRecordsParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.parse
    """
    @patch("lib.packet.packet_base.PayloadBase.parse", autospec=True)
    @patch("lib.packet.pcb.PathSegment.deserialize", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.path_mgmt.PathSegmentInfo", autospec=True)
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
    @patch("lib.packet.pcb.PathSegment.serialize", spec_set=['LEN'],
           new_callable=MagicMock)
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
    @patch("lib.packet.packet_base.PayloadBase.__init__", autospec=True)
    def test_basic(self, init):
        les_inf = LeaseInfo()
        ntools.eq_(les_inf.seg_type, PathSegmentType.DOWN)
        ntools.eq_(les_inf.isd_id, 0)
        ntools.eq_(les_inf.ad_id, 0)
        ntools.eq_(les_inf.exp_time, 0)
        ntools.eq_(les_inf.seg_id, b"")
        init.assert_called_once_with(les_inf)

    @patch("lib.packet.path_mgmt.LeaseInfo.parse", autospec=True)
    def test_raw(self, parse):
        les_inf = LeaseInfo("data")
        parse.assert_called_once_with(les_inf, "data")


class TestLeaseInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.LeaseInfo.parse
    """
    @patch("lib.packet.path_mgmt.ISD_AD.from_raw", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.packet_base.PayloadBase.parse", autospec=True)
    def test_basic(self, parse, isd_ad):
        les_inf = LeaseInfo()
        data = bytes.fromhex('0e 021004c6 01020304') + \
            b"superlengthybigstringoflength32."
        isd_ad.return_value = (0x021, 0x004c6)
        les_inf.parse(data)
        parse.assert_called_once_with(les_inf, data)
        ntools.eq_(les_inf.seg_type, 0x0e)
        isd_ad.assert_called_once_with(data[1:1 + ISD_AD.LEN])
        ntools.eq_(les_inf.isd_id, 0x021)
        ntools.eq_(les_inf.ad_id, 0x004c6)
        ntools.eq_(les_inf.exp_time, 0x01020304)
        ntools.eq_(les_inf.seg_id, b"superlengthybigstringoflength32.")

    @patch("lib.packet.packet_base.PayloadBase.parse", autospec=True)
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
    Unit tests for lib.packet.path_mgmt.LeaseInfo.pack
    """
    @patch("lib.packet.path_mgmt.ISD_AD", autospec=True)
    def test_basic(self, isd_ad):
        les_inf = LeaseInfo()
        les_inf.seg_type = 0x0e
        les_inf.isd_id = 0x021
        les_inf.ad_id = 0x004c6
        les_inf.exp_time = 0x01020304
        les_inf.seg_id = b"superlengthybigstringoflength32."
        data = bytes.fromhex('0e 021004c6 01020304') + \
            b"superlengthybigstringoflength32."
        isd_ad_mock = MagicMock(spec_set=['pack'])
        isd_ad_mock.pack.return_value = bytes.fromhex('021004c6')
        isd_ad.return_value = isd_ad_mock
        ntools.eq_(les_inf.pack(), data)
        isd_ad.assert_called_once_with(0x021, 0x004c6)
        isd_ad_mock.pack.assert_called_once_with()


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
    @patch("lib.packet.packet_base.PayloadBase.__init__", autospec=True)
    def test_basic(self, init):
        pth_seg_les = PathSegmentLeases()
        ntools.eq_(pth_seg_les.nleases, 0)
        ntools.eq_(pth_seg_les.leases, [])
        init.assert_called_once_with(pth_seg_les)

    @patch("lib.packet.path_mgmt.PathSegmentLeases.parse", autospec=True)
    def test_raw(self, parse):
        pth_seg_les = PathSegmentLeases("data")
        parse.assert_called_once_with(pth_seg_les, "data")


class TestPathSegmentLeasesParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentLeases.parse
    """
    @patch("lib.packet.path_mgmt.LeaseInfo", autospec=True)
    @patch("lib.packet.packet_base.PayloadBase.parse", autospec=True)
    def test_basic(self, parse, les_inf):
        pth_seg_les = PathSegmentLeases()
        data = struct.pack("!B", 0x04) + b"abcd"
        les_inf.LEN = 1
        les_inf.side_effect = ["data0", "data1", "data2", "data3"]
        pth_seg_les.parse(data)
        parse.assert_called_once_with(pth_seg_les, data)
        ntools.eq_(pth_seg_les.nleases, 0x04)
        les_inf.assert_has_calls([call(b"a"), call(b"b"), call(b"c"),
                                  call(b"d")])
        for i in range(0x04):
            ntools.eq_(pth_seg_les.leases[i], "data" + str(i))


class TestPathSegmentLeasesPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentLeases.pack
    """
    def test_basic(self):
        pth_seg_les = PathSegmentLeases()
        pth_seg_les.nleases = 0x04
        data = struct.pack("!B", 0x04)
        for i in range(0x04):
            pth_seg_les.leases.append(MagicMock(spec_set=['pack']))
            pth_seg_les.leases[i].pack.return_value = struct.pack("!B", i)
            data += struct.pack("!B", i)
        ntools.eq_(pth_seg_les.pack(), data)
        for i in range(0x04):
            pth_seg_les.leases[i].pack.assert_called_once_with()


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
    @patch("lib.packet.packet_base.PayloadBase.__init__", autospec=True)
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

    @patch("lib.packet.path_mgmt.RevocationInfo.parse", autospec=True)
    def test_raw(self, parse):
        rev_inf = RevocationInfo("data")
        parse.assert_called_once_with(rev_inf, "data")


class TestRevocationInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.parse
    """
    def test_basic(self):
        rev_inf = RevocationInfo()
        data = struct.pack("!B", 0b00000101) + \
            b"superlengthybigstringoflength321" \
            b"superlengthybigstringoflength322"
        rev_inf.parse(data)
        ntools.eq_(rev_inf.rev_type, 0b101)
        ntools.eq_(rev_inf.incl_seg_id, 0b0)
        ntools.eq_(rev_inf.incl_hop, 0b0)
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
            b"superlengthybigstringoflength321" \
            b"superlengthybigstringoflength322" \
            b"superlengthybigstringoflength323" \
            b"superlengthybigstringoflength324" \
            b"superlengthybigstringoflength325"
        rev_inf.parse(data)
        ntools.eq_(rev_inf.rev_type, 0b011)
        ntools.eq_(rev_inf.incl_seg_id, 0b1)
        ntools.eq_(rev_inf.incl_hop, 0b1)
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
    Unit tests for lib.packet.path_mgmt.RevocationInfo.pack
    """
    def test_basic(self):
        rev_inf = RevocationInfo()
        rev_inf.rev_type = 0b00000101
        rev_inf.incl_seg_id = 0b0
        rev_inf.incl_hop = 0b0
        rev_inf.rev_token1 = b"superlengthybigstringoflength321"
        rev_inf.proof1 = b"superlengthybigstringoflength322"
        data = struct.pack("!B", 0b00000101) + \
            b"superlengthybigstringoflength321" + \
            b"superlengthybigstringoflength322"
        ntools.eq_(rev_inf.pack(), data)

    def test_var_size(self):
        rev_inf = RevocationInfo()
        rev_inf.rev_type = 0b00011011
        rev_inf.incl_seg_id = 0b1
        rev_inf.incl_hop = 0b1
        rev_inf.seg_id = b"superlengthybigstringoflength321"
        rev_inf.rev_token1 = b"superlengthybigstringoflength322"
        rev_inf.proof1 = b"superlengthybigstringoflength323"
        rev_inf.rev_token2 = b"superlengthybigstringoflength324"
        rev_inf.proof2 = b"superlengthybigstringoflength325"
        data = struct.pack("!B", 0b00011011) + \
            b"superlengthybigstringoflength321" \
            b"superlengthybigstringoflength322" \
            b"superlengthybigstringoflength323" \
            b"superlengthybigstringoflength324" \
            b"superlengthybigstringoflength325"
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
    @patch("lib.packet.packet_base.PayloadBase.__init__", autospec=True)
    def test_basic(self, init):
        rev_pld = RevocationPayload()
        ntools.eq_(rev_pld.rev_infos, [])
        init.assert_called_once_with(rev_pld)

    @patch("lib.packet.path_mgmt.RevocationPayload.parse", autospec=True)
    def test_raw(self, parse):
        rev_pld = RevocationPayload("data")
        parse.assert_called_once_with(rev_pld, "data")


class TestRevocationPayloadParse(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationPayload.parse
    """
    @patch("lib.packet.path_mgmt.RevocationInfo", autospec=True)
    @patch("lib.packet.packet_base.PayloadBase.parse", autospec=True)
    def test_basic(self, parse, rev_inf):
        rev_pld = RevocationPayload()
        data = "abcde"
        side_effect = []
        for i in range(len(data)):
            side_effect.append(MagicMock(spec_set=['__len__', 'parsed']))
            side_effect[i].__len__.return_value = 1
            side_effect[i].parsed = True
        rev_inf.MAX_LEN = 1
        rev_inf.side_effect = side_effect
        rev_pld.parse(data)
        parse.assert_called_once_with(rev_pld, data)
        rev_inf.assert_has_calls([call(i) for i in data])
        ntools.eq_(rev_pld.rev_infos[i], side_effect[i])

    @patch("lib.packet.packet_base.PayloadBase.parse", autospec=True)
    def test_len(self, parse):
        rev_pld = RevocationPayload()
        rev_pld.parse("smalldata")
        parse.assert_called_once_with(rev_pld, "smalldata")
        ntools.eq_(rev_pld.rev_infos, [])


class TestRevocationPayloadPack(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationPayload.pack
    """
    def test_basic(self):
        rev_pld = RevocationPayload()
        data = b""
        for i in range(0x04):
            rev_pld.rev_infos.append(MagicMock(spec_set=['pack']))
            rev_pld.rev_infos[i].pack.return_value = struct.pack("!B", i)
            data += struct.pack("!B", i)
        ntools.eq_(rev_pld.pack(), data)
        for i in range(0x04):
            rev_pld.rev_infos[i].pack.assert_called_once_with()


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
    @patch("lib.packet.scion.SCIONPacket.__init__", autospec=True)
    def test_basic(self, init):
        pth_mgmt_pkt = PathMgmtPacket()
        ntools.eq_(pth_mgmt_pkt.type, 0)
        init.assert_called_once_with(pth_mgmt_pkt)

    @patch("lib.packet.path_mgmt.PathMgmtPacket.parse", autospec=True)
    def test_raw(self, parse):
        pth_mgmt_pkt = PathMgmtPacket("data")
        parse.assert_called_once_with(pth_mgmt_pkt, "data")


class TestPathMgmtPacketParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathMgmtPacket.parse
    """
    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.path_mgmt.PathSegmentInfo", autospec=True)
    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test_request(self, parse, inf, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", PathMgmtType.REQUEST) + \
            b"data1"
        inf.return_value = "data2"
        pth_mgmt_pkt.parse("data3")
        parse.assert_called_once_with(pth_mgmt_pkt, "data3")
        ntools.eq_(pth_mgmt_pkt.type, PathMgmtType.REQUEST)
        inf.assert_called_once_with(b"data1")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "data2")

    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.path_mgmt.PathSegmentRecords", autospec=True)
    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test_records(self, parse, rec, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", PathMgmtType.RECORDS) + \
            b"data1"
        rec.return_value = "data2"
        pth_mgmt_pkt.parse("data3")
        parse.assert_called_once_with(pth_mgmt_pkt, "data3")
        ntools.eq_(pth_mgmt_pkt.type, PathMgmtType.RECORDS)
        rec.assert_called_once_with(b"data1")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "data2")

    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.path_mgmt.PathSegmentLeases", autospec=True)
    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test_leases(self, parse, les, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", PathMgmtType.LEASES) + \
            b"data1"
        les.return_value = "data2"
        pth_mgmt_pkt.parse("data3")
        parse.assert_called_once_with(pth_mgmt_pkt, "data3")
        ntools.eq_(pth_mgmt_pkt.type, PathMgmtType.LEASES)
        les.assert_called_once_with(b"data1")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "data2")

    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.path_mgmt.RevocationPayload", autospec=True)
    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
    def test_revocation(self, parse, rev, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", PathMgmtType.REVOCATIONS) + \
            b"data1"
        rev.return_value = "data2"
        pth_mgmt_pkt.parse("data3")
        parse.assert_called_once_with(pth_mgmt_pkt, "data3")
        ntools.eq_(pth_mgmt_pkt.type, PathMgmtType.REVOCATIONS)
        rev.assert_called_once_with(b"data1")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "data2")

    @patch("lib.packet.scion.SCIONPacket.parse", autospec=True)
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
    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONPacket.pack", autospec=True)
    def test_basic(self, pack_scion, set_pld):
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt.type = 3
        pack_scion.return_value = "data1"
        pth_mgmt_pkt._payload = MagicMock(spec_set=['pack'])
        pth_mgmt_pkt.payload.pack.return_value = b"data2"
        ntools.eq_(pth_mgmt_pkt.pack(), "data1")
        pth_mgmt_pkt.payload.pack.assert_called_once_with()
        set_pld.assert_called_once_with(pth_mgmt_pkt,
                                        struct.pack("!B", 3) + b"data2")
        pack_scion.assert_called_once_with(pth_mgmt_pkt)

    @patch("lib.packet.scion.SCIONPacket.pack", autospec=True)
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
    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.packet_base.PacketBase.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.scion_addr.SCIONAddr.from_values", spec_set=[],
           new_callable=MagicMock)
    def test_to_scionaddr(self, from_values, from_values_hdr, set_hdr, set_pld):
        src_addr = ISD_AD("isd", "ad")
        dst_addr = SCIONAddr()
        from_values.return_value = "data1"
        from_values_hdr.return_value = "data2"
        pth_mgmt_pkt = PathMgmtPacket.from_values("type", "payload", "path",
                                                  src_addr, dst_addr)
        from_values.assert_called_once_with("isd", "ad", PacketType.PATH_MGMT)
        from_values_hdr.assert_called_once_with("data1", dst_addr, "path")
        set_hdr.assert_called_once_with(pth_mgmt_pkt, "data2")
        ntools.eq_(pth_mgmt_pkt.type, "type")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "payload")
        ntools.assert_is_instance(pth_mgmt_pkt, PathMgmtPacket)

    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.packet_base.PacketBase.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.scion_addr.SCIONAddr.from_values", spec_set=[],
           new_callable=MagicMock)
    def test_frm_scionaddr(self, frm_values, from_values_hdr, set_hdr, set_pld):
        src_addr = SCIONAddr()
        dst_addr = ISD_AD("isd", "ad")
        frm_values.return_value = "data1"
        from_values_hdr.return_value = "data2"
        pth_mgmt_pkt = PathMgmtPacket.from_values("type", "payload", "path",
                                                  src_addr, dst_addr)
        frm_values.assert_called_once_with("isd", "ad", PacketType.PATH_MGMT)
        from_values_hdr.assert_called_once_with(src_addr, "data1", "path")
        set_hdr.assert_called_once_with(pth_mgmt_pkt, "data2")
        ntools.eq_(pth_mgmt_pkt.type, "type")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "payload")

    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.packet_base.PacketBase.set_hdr", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values", spec_set=[],
           new_callable=MagicMock)
    def test_invalid(self, from_values, set_hdr, set_pld):
        from_values.return_value = "data"
        pth_mgmt_pkt = PathMgmtPacket.from_values("type", "payload", "path",
                                                  "src_addr", "dst_addr")
        from_values.assert_called_once_with("src_addr", "dst_addr", "path")
        set_hdr.assert_called_once_with(pth_mgmt_pkt, "data")
        ntools.eq_(pth_mgmt_pkt.type, "type")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "payload")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
