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
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.path_mgmt import (
    PathSegmentInfo,
    PathSegmentRecords,
    RevocationInfo,
    parse_pathmgmt_payload,
)
from lib.types import PathMgmtType
from test.testcommon import assert_these_calls, create_mock


class TestPathSegmentInfoInit(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.__init__
    """
    @patch("lib.packet.path_mgmt.PathSegmentInfo._parse", autospec=True)
    @patch("lib.packet.path_mgmt.PathMgmtPayloadBase.__init__", autospec=True)
    def test_full(self, super_init, parse):
        inst = PathSegmentInfo("data")
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.eq_(inst.seg_type, 0)
        ntools.eq_(inst.src_isd, 0)
        ntools.eq_(inst.dst_isd, 0)
        ntools.eq_(inst.src_ad, 0)
        ntools.eq_(inst.dst_ad, 0)
        parse.assert_called_once_with(inst, "data")


class TestPathSegmentInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo._parse
    """
    @patch("lib.packet.path_mgmt.ISD_AD.from_raw", new_callable=create_mock)
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    def test(self, raw, isd_ad):
        inst = PathSegmentInfo()
        data = create_mock(["pop"])
        data.pop.side_effect = ("seg type", "src isd-ad", "dst isd-ad")
        raw.return_value = data
        isd_ad.side_effect = [("src isd", "src ad"), ("dst isd", "dst ad")]
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        ntools.eq_(inst.seg_type, "seg type")
        assert_these_calls(isd_ad, (call("src isd-ad"), call("dst isd-ad")))
        ntools.eq_(inst.src_isd, "src isd")
        ntools.eq_(inst.src_ad, "src ad")
        ntools.eq_(inst.dst_isd, "dst isd")
        ntools.eq_(inst.dst_ad, "dst ad")


class TestPathSegmentInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.from_values
    """
    def test(self):
        inst = PathSegmentInfo.from_values(
            "seg type", "src isd", "src ad", "dst isd", "dst ad")
        # Tests
        ntools.assert_is_instance(inst, PathSegmentInfo)
        ntools.eq_(inst.seg_type, "seg type")
        ntools.eq_(inst.src_isd, "src isd")
        ntools.eq_(inst.src_ad, "src ad")
        ntools.eq_(inst.dst_isd, "dst isd")
        ntools.eq_(inst.dst_ad, "dst ad")


class TestPathSegmentInfoPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentInfo.pack
    """
    @patch("lib.packet.path_mgmt.ISD_AD", autospec=True)
    def test_basic(self, isd_ad):
        inst = PathSegmentInfo()
        inst.seg_type = 0x0e
        inst.src_isd = "src isd"
        inst.src_ad = "src ad"
        inst.dst_isd = "dst isd"
        inst.dst_ad = "dst ad"
        src_isd_ad = create_mock(['pack'])
        src_isd_ad.pack.return_value = b"src packed"
        dst_isd_ad = create_mock(['pack'])
        dst_isd_ad.pack.return_value = b"dst packed"
        isd_ad.side_effect = (src_isd_ad, dst_isd_ad)
        expected = b"".join([bytes([0x0e]), b"src packed", b"dst packed"])
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        assert_these_calls(isd_ad, (
            call("src isd", "src ad"), call("dst isd", "dst ad")))


class TestPathSegmentRecordsInit(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.__init__
    """
    @patch("lib.packet.path_mgmt.PathSegmentRecords._parse", autospec=True)
    @patch("lib.packet.path_mgmt.PathMgmtPayloadBase.__init__", autospec=True)
    def test_full(self, super_init, parse):
        inst = PathSegmentRecords("data")
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.assert_is_none(inst.info)
        ntools.assert_is_none(inst.pcbs)
        parse.assert_called_once_with(inst, "data")


class TestPathSegmentRecordsParse(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.parse
    """
    @patch("lib.packet.pcb.PathSegment.deserialize", new_callable=create_mock)
    @patch("lib.packet.path_mgmt.PathSegmentInfo", autospec=True)
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    def test(self, raw, pth_seg_info, deserialize):
        inst = PathSegmentRecords()
        inst.NAME = "PathSegmentRecords"
        data = create_mock(["pop"])
        data.pop.side_effect = ("raw info", "raw pcbs")
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "PathSegmentRecords", inst.MIN_LEN,
                                    min_=True)
        pth_seg_info.assert_called_once_with("raw info")
        deserialize.assert_called_once_with("raw pcbs")
        ntools.eq_(inst.info, pth_seg_info.return_value)
        ntools.eq_(inst.pcbs, deserialize.return_value)


class TestPathSegmentRecordsFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.from_values
    """
    def test(self):
        info = create_mock(class_=PathSegmentInfo)
        inst = PathSegmentRecords.from_values(info, "pcbs")
        # Tests
        ntools.assert_is_instance(inst, PathSegmentRecords)
        ntools.eq_(inst.info, info)
        ntools.eq_(inst.pcbs, "pcbs")


class TestPathSegmentRecordsPack(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.pack
    """
    @patch("lib.packet.path_mgmt.PathSegment.serialize",
           new_callable=create_mock)
    def test(self, serialize):
        inst = PathSegmentRecords()
        inst.info = create_mock(["pack"])
        inst.info.pack.return_value = b"packed info"
        inst.pcbs = "pcbs"
        serialize.return_value = b"packed pcbs"
        expected = b"".join([b"packed info", b"packed pcbs"])
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        serialize.assert_called_once_with("pcbs")


class TestRevocationInfoInit(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.__init__
    """
    @patch("lib.packet.path_mgmt.RevocationInfo._parse", autospec=True)
    @patch("lib.packet.path_mgmt.PathMgmtPayloadBase.__init__", autospec=True)
    def test_full(self, super_init, parse):
        inst = RevocationInfo("data")
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.eq_(inst.rev_token, b"")
        parse.assert_called_once_with(inst, "data")


class TestRevocationInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo._parse
    """
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    def test(self, raw):
        inst = RevocationInfo()
        data = create_mock(["pop"])
        data.pop.return_value = bytes(range(32))
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "RevocationInfo", inst.LEN)
        ntools.eq_(inst.rev_token, bytes(range(32)))


class TestRevocationInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.from_values
    """
    def test(self):
        inst = RevocationInfo.from_values("rev token")
        # Tests
        ntools.assert_is_instance(inst, RevocationInfo)
        ntools.eq_(inst.rev_token, "rev token")


class TestRevocationInfoPack(object):
    """
    Unit tests for lib.packet.path_mgmt.RevocationInfo.pack
    """
    def test(self):
        inst = RevocationInfo()
        inst.rev_token = bytes(range(32))
        # Call
        ntools.eq_(inst.pack(), bytes(range(32)))


class TestParsePathMgmtPayload(object):
    """
    Unit tests for lib.packet.path_mgmt.parse_pathmgmt_payload
    """
    @patch("lib.packet.path_mgmt.IFStateRequest", autospec=True)
    @patch("lib.packet.path_mgmt.IFStatePayload", autospec=True)
    @patch("lib.packet.path_mgmt.RevocationInfo", autospec=True)
    @patch("lib.packet.path_mgmt.PathRecordsSync", autospec=True)
    @patch("lib.packet.path_mgmt.PathRecordsReg", autospec=True)
    @patch("lib.packet.path_mgmt.PathRecordsReply", autospec=True)
    @patch("lib.packet.path_mgmt.PathSegmentInfo", autospec=True)
    def _check(self, type_, seg_info, rec_rep, rec_reg, rec_sync, rev_info,
               if_pld, if_req):
        class_map = {
            PathMgmtType.REQUEST: seg_info,
            PathMgmtType.REPLY: rec_rep,
            PathMgmtType.REG: rec_reg,
            PathMgmtType.SYNC: rec_sync,
            PathMgmtType.REVOCATION: rev_info,
            PathMgmtType.IFSTATE_INFO: if_pld,
            PathMgmtType.IFSTATE_REQ: if_req,
        }
        data = create_mock(["pop"])
        data.pop.return_value = b"payload"
        # Call
        inst = parse_pathmgmt_payload(type_, data)
        # Tests
        ntools.eq_(inst, class_map[type_].return_value)

    def test(self):
        for type_ in (
            PathMgmtType.REQUEST, PathMgmtType.REPLY, PathMgmtType.REG,
            PathMgmtType.SYNC, PathMgmtType.REVOCATION,
            PathMgmtType.IFSTATE_INFO, PathMgmtType.IFSTATE_REQ,
        ):
            yield self._check, type_

    def test_unsupported(self):
        # Call
        ntools.assert_raises(SCIONParseError, parse_pathmgmt_payload,
                             "unknown type", "data")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
