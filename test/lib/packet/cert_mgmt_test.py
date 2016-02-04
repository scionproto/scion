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
:mod:`lib_packet_cert_mgmt_test` --- lib.packet.cert_mgmt unit tests
====================================================================
"""
# Stdlib
from unittest.mock import patch, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.cert_mgmt import (
    CertChainReply,
    CertChainRequest,
    TRCReply,
    TRCRequest,
    _TYPE_MAP,
    parse_certmgmt_payload,
)
from test.testcommon import (
    assert_these_call_lists,
    create_mock,
)


class TestCertChainRequestParse(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainRequest._parse
    """
    @patch("lib.packet.cert_mgmt.ISD_AD.from_raw", new_callable=create_mock)
    @patch("lib.packet.cert_mgmt.Raw", autospec=True)
    def test(self, raw, isd_ad):
        inst = CertChainRequest()
        data = create_mock(["pop"])
        data.pop.side_effect = ("target ISD-AD", bytes.fromhex("01020304"))
        raw.return_value = data
        isd_ad.return_value = ("target isd", "target ad")
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        isd_ad.assert_called_once_with("target ISD-AD")
        ntools.eq_(inst.isd_id, "target isd")
        ntools.eq_(inst.ad_id, "target ad")
        ntools.eq_(inst.version, 0x01020304)


class TestCertChainRequestFromValues(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainRequest.from_values
    """
    def test_full(self):
        inst = CertChainRequest.from_values("isd", "ad", "ver")
        # Tests
        ntools.assert_is_instance(inst, CertChainRequest)
        ntools.eq_(inst.isd_id, "isd")
        ntools.eq_(inst.ad_id, "ad")
        ntools.eq_(inst.version, "ver")


class TestCertChainRequestPack(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainRequest.pack
    """
    @patch("lib.packet.cert_mgmt.ISD_AD", autospec=True)
    def test(self, isd_ad):
        inst = CertChainRequest()
        inst.isd_id = "target isd"
        inst.ad_id = "target ad"
        inst.version = 0x01020304
        isd_ad_obj = create_mock(["pack"])
        isd_ad_obj.pack.return_value = b"target ISD-AD"
        isd_ad.return_value = isd_ad_obj
        expected = b"".join([b"target ISD-AD", bytes.fromhex("01020304")])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestCertChainReplyFromValues(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainReply.from_values
    """
    def test(self):
        inst = CertChainReply.from_values(b'cert_chain')
        # Tests
        ntools.assert_is_instance(inst, CertChainReply)
        ntools.eq_(inst.cert_chain, b'cert_chain')


class TestTRCRequestParse(object):
    """
    Unit tests for lib.packet.cert_mgmt.TRCRequest._parse
    """
    @patch("lib.packet.cert_mgmt.ISD_AD.from_raw", new_callable=create_mock)
    @patch("lib.packet.cert_mgmt.Raw", autospec=True)
    def test(self, raw, isd_ad):
        inst = TRCRequest()
        data = create_mock(["pop"])
        data.pop.side_effect = ("isd ad raw", bytes.fromhex("22222222"))
        raw.return_value = data
        isd_ad.return_value = "isd", "ad"
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        ntools.eq_(inst.isd_id, "isd")
        ntools.eq_(inst.ad_id, "ad")
        ntools.eq_(inst.version, 0x22222222)


class TestTRCRequestFromValues(object):
    """
    Unit tests for lib.packet.cert_mgmt.TRCRequest.from_values
    """
    def test_full(self):
        inst = TRCRequest.from_values("isd id", "ad id", "version")
        # Tests
        ntools.assert_is_instance(inst, TRCRequest)
        ntools.eq_(inst.isd_id, "isd id")
        ntools.eq_(inst.ad_id, "ad id")
        ntools.eq_(inst.version, "version")


class TestTRCRequestPack(object):
    """
    Unit tests for lib.packet.cert_mgmt.TRCRequest.pack
    """
    @patch("lib.packet.cert_mgmt.ISD_AD", autospec=True)
    def test(self, isd_ad):
        inst = TRCRequest()
        inst.isd_id = "isd id"
        inst.ad_id = "ad id"
        inst.version = 0x33333333
        isd_ad.return_value.pack.return_value = bytes.fromhex("11111111")
        expected = bytes.fromhex("11111111 33333333")
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        assert_these_call_lists(isd_ad, [call("isd id", "ad id").pack()])


class TestTRCReplyFromValues(object):
    """
    Unit tests for lib.packet.cert_mgmt.TRCReply.from_values
    """
    def test(self):
        trc = "trc"
        inst = TRCReply.from_values(trc)
        # Tests
        ntools.assert_is_instance(inst, TRCReply)
        ntools.eq_(inst.trc, trc)


class TestParseCertMgmtPayload(object):
    """
    Unit tests for lib.packet.cert_mgmt.parse_certmgmt_payload
    """
    @patch("lib.packet.cert_mgmt._TYPE_MAP", new_callable=dict)
    def _check_supported(self, type_, type_map):
        type_map[0] = create_mock(), 20
        type_map[1] = create_mock(), None
        handler, len_ = type_map[type_]
        data = create_mock(["pop"])
        # Call
        ntools.eq_(parse_certmgmt_payload(type_, data), handler.return_value)
        # Tests
        data.pop.assert_called_once_with(len_)
        handler.assert_called_once_with(data.pop.return_value)

    def test_supported(self):
        for type_ in (0, 1):
            yield self._check_supported, type_

    def test_unsupported(self):
        with patch.dict(_TYPE_MAP, clear=True):
            ntools.assert_raises(SCIONParseError, parse_certmgmt_payload, 0,
                                 "data")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
