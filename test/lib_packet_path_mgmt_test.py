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
    IFStateInfo,
    IFStatePayload,
    IFStateRequest,
    PathSegmentInfo,
    PathSegmentRecords,
    RevocationInfo,
    parse_pathmgmt_payload,
)
from test.testcommon import (
    assert_these_call_lists,
    assert_these_calls,
    create_mock,
)


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
        isd_ad_obj = create_mock(['pack'])
        isd_ad_obj.pack.side_effect = b"src packed", b"dst packed"
        isd_ad.return_value = isd_ad_obj
        expected = b"".join([bytes([0x0e]), b"src packed", b"dst packed"])
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        assert_these_call_lists(isd_ad, [
            call("src isd", "src ad").pack(), call("dst isd", "dst ad").pack()])


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


class TestPathSegmentRecordsLen(object):
    """
    Unit tests for lib.packet.path_mgmt.PathSegmentRecords.__len__
    """
    def test(self):
        inst = PathSegmentRecords()
        inst.info = range(5)
        inst.pcbs = [range(5) for x in range(5)]
        # Call
        ntools.eq_(len(inst), 30)


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


class TestIFStateInfoParse(object):
    """
    Unit tests for lib.packet.path_mgmt.IFStateInfo._parse
    """
    @patch("lib.packet.path_mgmt.RevocationInfo", autospec=True)
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    def test(self, raw, rev_info_cls):
        inst = IFStateInfo()
        data = create_mock(["pop"])
        data.pop.side_effect = bytes.fromhex("00001111"), "rev info"
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        ntools.eq_(inst.if_id, 0x0000)
        ntools.eq_(inst.state, 0x1111)
        rev_info_cls.assert_called_once_with("rev info")
        ntools.eq_(inst.rev_info, rev_info_cls.return_value)


class TestIFStateInfoFromValues(object):
    """
    Unit tests for lib.packet.path_mgmt.IFStateInfo.from_values
    """
    @patch("lib.packet.path_mgmt.RevocationInfo.from_values",
           new_callable=create_mock)
    def test(self, rev_from_values):
        inst = IFStateInfo.from_values("if id", "state", b"rev token")
        # Tests
        ntools.assert_is_instance(inst, IFStateInfo)
        ntools.eq_(inst.if_id, "if id")
        ntools.eq_(inst.state, "state")
        rev_from_values.assert_called_once_with(b"rev token")
        ntools.eq_(inst.rev_info, rev_from_values.return_value)


class TestIFStateInfoPack(object):
    """
    Unit tests for lib.packet.path_mgmt.IFStateInfo.pack
    """
    def test(self):
        inst = IFStateInfo()
        inst.if_id = 0x0000
        inst.state = 0x1111
        inst.rev_info = create_mock(["pack"])
        inst.rev_info.pack.return_value = b"rev token"
        expected = bytes.fromhex("00001111") + b"rev token"
        # Call
        ntools.eq_(inst.pack(), expected)


class TestIFStatePayloadParse(object):
    """
    Unit tests for lib.packet.path_mgmt.IFStatePayload._parse
    """
    @patch("lib.packet.path_mgmt.IFStateInfo", autospec=True)
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    def test(self, raw, if_state_info):
        inst = IFStatePayload()
        data = create_mock(["__len__", "pop"])
        data.__len__.side_effect = 3, 2, 1, 0
        raw_state_infos = ["if_state%d" % i for i in range(3)]
        data.pop.side_effect = raw_state_infos
        raw.return_value = data
        state_infos = ["if state info %d" % i for i in range(3)]
        if_state_info.side_effect = state_infos
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.MIN_LEN, min_=True)
        assert_these_calls(if_state_info, [call(i) for i in raw_state_infos])
        ntools.eq_(inst.ifstate_infos, state_infos)


class TestIFStatePayloadPack(object):
    """
    Unit tests for lib.packet.path_mgmt.IFStatePayload.pack
    """
    def test(self):
        inst = IFStatePayload()
        for i in range(3):
            info = create_mock(["pack"])
            info.pack.return_value = bytes("info%d" % i, "ascii")
            inst.ifstate_infos.append(info)
        expected = b"info0" b"info1" b"info2"
        # Call
        ntools.eq_(inst.pack(), expected)


class TestIFStateRequestParse(object):
    """
    Unit tests for lib.packet.path_mgmt.IFStateRequest._parse
    """
    @patch("lib.packet.path_mgmt.IFStateInfo", autospec=True)
    @patch("lib.packet.path_mgmt.Raw", autospec=True)
    def test(self, raw, if_state_info):
        inst = IFStateRequest()
        data = create_mock(["__len__", "pop"])
        data.pop.return_value = bytes.fromhex("1234")
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        ntools.eq_(inst.if_id, 0x1234)


class TestIFStateRequestPack(object):
    """
    Unit tests for lib.packet.path_mgmt.IFStateRequest.pack
    """
    def test(self):
        inst = IFStateRequest()
        inst.if_id = 0x1234
        # Call
        ntools.eq_(inst.pack(), bytes.fromhex("1234"))


class TestParsePathMgmtPayload(object):
    """
    Unit tests for lib.packet.path_mgmt.parse_pathmgmt_payload
    """
    @patch("lib.packet.path_mgmt._TYPE_MAP", new_callable=dict)
    def _check_supported(self, type_, type_map):
        type_map[0] = create_mock(), 20
        type_map[1] = create_mock(), None
        handler, len_ = type_map[type_]
        data = create_mock(["pop"])
        # Call
        ntools.eq_(parse_pathmgmt_payload(type_, data), handler.return_value)
        # Tests
        data.pop.assert_called_once_with(len_)
        handler.assert_called_once_with(data.pop.return_value)

    def test_supported(self):
        for type_ in (0, 1):
            yield self._check_supported, type_

    def test_unsupported(self):
        # Call
        ntools.assert_raises(SCIONParseError, parse_pathmgmt_payload,
                             "unknown type", "data")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
