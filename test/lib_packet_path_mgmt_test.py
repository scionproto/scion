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
from lib.errors import SCIONParseError
from lib.packet.path_mgmt import (
    PathMgmtPacket,
    PathMgmtType,
    PathSegmentInfo,
    PathSegmentRecords,
    RevocationInfo,
)
from lib.packet.scion import PacketType
from lib.packet.scion_addr import ISD_AD, SCIONAddr
from test.testcommon import create_mock


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
    @patch("lib.packet.path_mgmt.PayloadBase.parse", autospec=True)
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    def test_basic(self, raw, parse, isd_ad):
        # Setup
        pth_seg_info = PathSegmentInfo()
        data = bytes.fromhex('0e 0bc0021d 021004c6')
        isd_ad.side_effect = [(0x0bc, 0x0021d), (0x021, 0x004c6)]
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.side_effect = (0x0e, "src_pop", "dst_pop")
        # Call
        pth_seg_info.parse(data)
        # Tests
        raw.assert_called_once_with(data, "PathSegmentInfo", pth_seg_info.LEN)
        parse.assert_called_once_with(pth_seg_info, data)
        ntools.eq_(pth_seg_info.type, 0x0e)
        isd_ad.assert_has_calls((call("src_pop"), call("dst_pop")))
        ntools.eq_(pth_seg_info.src_isd, 0x0bc)
        ntools.eq_(pth_seg_info.src_ad, 0x0021d)
        ntools.eq_(pth_seg_info.dst_isd, 0x021)
        ntools.eq_(pth_seg_info.dst_ad, 0x004c6)


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
    @patch("lib.packet.pcb.PathSegment.deserialize", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.path_mgmt.PathSegmentInfo", autospec=True)
    @patch("lib.packet.path_mgmt.PayloadBase.parse", autospec=True)
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    def test_basic(self, raw, parse_payload, pth_seg_info, deserialize):
        # Setup
        pth_seg_info.return_value = "data1"
        deserialize.return_value = "data2"
        pth_seg_info.LEN = PathSegmentInfo.LEN
        pth_seg_rec = PathSegmentRecords()
        data = b"randomstring"
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.side_effect = ("info", "deserialize")
        # Call
        pth_seg_rec.parse(data)
        # Tests
        parse_payload.assert_called_once_with(pth_seg_rec, data)
        raw.assert_called_once_with(data, "PathSegmentRecords",
                                    pth_seg_rec.MIN_LEN, min_=True)
        pth_seg_info.assert_called_once_with("info")
        deserialize.assert_called_once_with("deserialize")
        ntools.eq_(pth_seg_rec.info, "data1")
        ntools.eq_(pth_seg_rec.pcbs, "data2")


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
        ntools.eq_(pth_seg_rec.pack(), "data1" + "data2")
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


class TestRevocationInfoInit(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.__init__
    """
    @patch("lib.packet.packet_base.PayloadBase.__init__", autospec=True)
    def test_basic(self, init):
        rev_inf = RevocationInfo()
        ntools.eq_(rev_inf.rev_token, b"")
        ntools.eq_(rev_inf.proof, b"")
        init.assert_called_once_with(rev_inf)

    @patch("lib.packet.path_mgmt.RevocationInfo.parse", autospec=True)
    def test_raw(self, parse):
        rev_inf = RevocationInfo("data")
        parse.assert_called_once_with(rev_inf, "data")


class TestRevocationInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.parse
    """
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    def test_basic(self, raw):
        # Setup
        rev_inf = RevocationInfo()
        data = (b"superlengthybigstringoflength321" +
                b"superlengthybigstringoflength322")
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.side_effect = (data[:],)
        # Call
        rev_inf.parse(data)
        # Tests
        raw.assert_called_once_with(data, "RevocationInfo", rev_inf.LEN)
        ntools.eq_(rev_inf.rev_token, b"superlengthybigstringoflength321")
        ntools.eq_(rev_inf.proof, b"superlengthybigstringoflength322")
        ntools.eq_(rev_inf.raw, data)
        ntools.assert_true(rev_inf.parsed)


class TestRevocationInfoPack(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.pack
    """
    def test_basic(self):
        rev_inf = RevocationInfo()
        rev_inf.rev_token = b"superlengthybigstringoflength321"
        rev_inf.proof = b"superlengthybigstringoflength322"
        data = (b"superlengthybigstringoflength321" +
                b"superlengthybigstringoflength322")
        ntools.eq_(rev_inf.pack(), data)


class TestRevocationInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.from_values
    """
    def test_basic(self):
        rev_inf = RevocationInfo.from_values("data1", "data2")
        ntools.eq_(rev_inf.rev_token, "data1")
        ntools.eq_(rev_inf.proof, "data2")
        ntools.assert_is_instance(rev_inf, RevocationInfo)


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
    @patch("lib.packet.path_mgmt.IFStateRequest", autospec=True)
    @patch("lib.packet.path_mgmt.IFStatePayload", autospec=True)
    @patch("lib.packet.path_mgmt.RevocationInfo", autospec=True)
    @patch("lib.packet.path_mgmt.PathSegmentRecords", autospec=True)
    @patch("lib.packet.path_mgmt.PathSegmentInfo", autospec=True)
    @patch("lib.packet.path_mgmt.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    @patch("lib.packet.path_mgmt.SCIONPacket.parse", autospec=True)
    def _check_success(self, type_, scion_parse, raw, set_payload,
                       seg_info, seg_recs, rev_info, ifstate_payload,
                       ifstate_request):
        # Setup
        type_map = {
            PathMgmtType.REQUEST: seg_info,
            PathMgmtType.RECORDS: seg_recs,
            PathMgmtType.REVOCATION: rev_info,
            PathMgmtType.IFSTATE_INFO: ifstate_payload,
            PathMgmtType.IFSTATE_REQ: ifstate_request,
        }
        target = type_map[type_]
        raw.return_value = MagicMock(spec_set=["pop"])
        raw.return_value.pop.side_effect = (type_, "pop data")
        data = b"data"
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = b"payload"
        seg_info.LEN = PathSegmentInfo.LEN
        # Call
        pth_mgmt_pkt.parse(data)
        # Tests
        scion_parse.assert_called_once_with(pth_mgmt_pkt, data)
        raw.assert_called_once_with(b"payload", "PathMgmtPacket",
                                    pth_mgmt_pkt.MIN_LEN, min_=True)
        ntools.eq_(pth_mgmt_pkt.type, type_)
        target.assert_called_once_with("pop data")
        set_payload.assert_called_once_with(pth_mgmt_pkt, target.return_value)

    def test_success(self):
        for type_ in (PathMgmtType.REQUEST, PathMgmtType.RECORDS,
                      PathMgmtType.REVOCATION, PathMgmtType.IFSTATE_INFO,
                      PathMgmtType.IFSTATE_REQ):
            yield self._check_success, type_

    @patch("lib.packet.path_mgmt.SCIONPacket.parse", autospec=True)
    def test_invalid_type(self, scion_parse):
        # Setup
        pth_mgmt_pkt = PathMgmtPacket()
        pth_mgmt_pkt._payload = struct.pack("!B", 255)
        # Call
        ntools.assert_raises(SCIONParseError, pth_mgmt_pkt.parse, b"data")


class TestPathMgmtPacketPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathMgmtPacket.pack
    """
    @patch("lib.packet.scion.SCIONPacket.pack", autospec=True)
    def test_basic(self, pack_scion):
        pth_mgmt_pkt = PathMgmtPacket()
        payload = create_mock(["pack"])
        payload.pack.return_value = b"data"
        pth_mgmt_pkt._payload = payload
        pth_mgmt_pkt.set_payload = create_mock()
        pth_mgmt_pkt.type = 3
        # Call
        ntools.eq_(pth_mgmt_pkt.pack(), pack_scion.return_value)
        # Tests
        payload.pack.assert_called_once_with()
        pth_mgmt_pkt.set_payload.assert_called_once_with(
            struct.pack("!B", 3) + b"data")
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
    @patch("lib.packet.scion.SCIONHeader.from_values", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.scion_addr.SCIONAddr.from_values", spec_set=[],
           new_callable=MagicMock)
    def test_to_scionaddr(self, from_values, from_values_hdr, set_pld):
        src_addr = ISD_AD("isd", "ad")
        dst_addr = SCIONAddr()
        from_values.return_value = "data1"
        from_values_hdr.return_value = "data2"
        pth_mgmt_pkt = PathMgmtPacket.from_values("type", "payload", "path",
                                                  src_addr, dst_addr)
        from_values.assert_called_once_with("isd", "ad", PacketType.PATH_MGMT)
        from_values_hdr.assert_called_once_with("data1", dst_addr, "path")
        ntools.eq_(pth_mgmt_pkt.hdr, "data2")
        ntools.eq_(pth_mgmt_pkt.type, "type")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "payload")
        ntools.assert_is_instance(pth_mgmt_pkt, PathMgmtPacket)

    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values", spec_set=[],
           new_callable=MagicMock)
    @patch("lib.packet.scion_addr.SCIONAddr.from_values", spec_set=[],
           new_callable=MagicMock)
    def test_frm_scionaddr(self, frm_values, from_values_hdr, set_pld):
        src_addr = SCIONAddr()
        dst_addr = ISD_AD("isd", "ad")
        frm_values.return_value = "data1"
        from_values_hdr.return_value = "data2"
        pth_mgmt_pkt = PathMgmtPacket.from_values("type", "payload", "path",
                                                  src_addr, dst_addr)
        frm_values.assert_called_once_with("isd", "ad", PacketType.PATH_MGMT)
        from_values_hdr.assert_called_once_with(src_addr, "data1", "path")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "payload")

    @patch("lib.packet.scion.SCIONPacket.set_payload", autospec=True)
    @patch("lib.packet.scion.SCIONHeader.from_values", spec_set=[],
           new_callable=MagicMock)
    def test_invalid(self, from_values, set_pld):
        from_values.return_value = "data"
        pth_mgmt_pkt = PathMgmtPacket.from_values("type", "payload", "path",
                                                  "src_addr", "dst_addr")
        from_values.assert_called_once_with("src_addr", "dst_addr", "path")
        set_pld.assert_called_once_with(pth_mgmt_pkt, "payload")

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
