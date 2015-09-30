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
from unittest.mock import patch, MagicMock, call

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.cert_mgmt import (
    CertChainRequest,
    CertChainReply,
    TRCReply,
)
from test.testcommon import assert_these_calls, create_mock


class TestCertChainRequestInit(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainRequest.__init__
    """
    @patch("lib.packet.cert_mgmt.CertChainRequest._parse", autospec=True)
    @patch("lib.packet.cert_mgmt.CertMgmtBase.__init__", autospec=True)
    def test_full(self, super_init, parse):
        inst = CertChainRequest("raw")
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.assert_is_none(inst.ingress_if)
        ntools.assert_is_none(inst.src_isd)
        ntools.assert_is_none(inst.src_ad)
        ntools.assert_is_none(inst.isd_id)
        ntools.assert_is_none(inst.ad_id)
        ntools.assert_is_none(inst.version)
        ntools.assert_is_none(inst.local)
        parse.assert_called_once_with(inst, "raw")


class TestCertChainRequestParse(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainRequest._parse
    """
    @patch("lib.packet.cert_mgmt.ISD_AD.from_raw", new_callable=create_mock)
    @patch("lib.packet.cert_mgmt.Raw", autospec=True)
    def test(self, raw, isd_ad):
        inst = CertChainRequest()
        data = create_mock(["pop"])
        data.pop.side_effect = (
            bytes.fromhex("1234"), "src ISD-AD", "target ISD-AD",
            bytes.fromhex("01020304"), int(False),
        )
        raw.return_value = data
        isd_ad.side_effect = (("src isd", "src ad"),
                              ("target isd", "target ad"))
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        assert_these_calls(isd_ad, (call("src ISD-AD"), call("target ISD-AD")))
        ntools.eq_(inst.ingress_if, 0x1234)
        ntools.eq_(inst.src_isd, "src isd")
        ntools.eq_(inst.src_ad, "src ad")
        ntools.eq_(inst.isd_id, "target isd")
        ntools.eq_(inst.ad_id, "target ad")
        ntools.eq_(inst.version, 0x01020304)
        ntools.eq_(inst.local, False)


class TestCertChainRequestFromValues(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainRequest.from_values
    """
    def test_full(self):
        inst = CertChainRequest.from_values(
            "if", "src isd", "src ad", "isd", "ad", "ver", local=False)
        # Tests
        ntools.assert_is_instance(inst, CertChainRequest)
        ntools.eq_(inst.ingress_if, "if")
        ntools.eq_(inst.src_isd, "src isd")
        ntools.eq_(inst.src_ad, "src ad")
        ntools.eq_(inst.isd_id, "isd")
        ntools.eq_(inst.ad_id, "ad")
        ntools.eq_(inst.version, "ver")
        ntools.eq_(inst.local, False)


class TestCertChainRequestPack(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainRequest.pack
    """
    @patch("lib.packet.cert_mgmt.ISD_AD", autospec=True)
    def test(self, isd_ad):
        inst = CertChainRequest()
        inst.ingress_if = 0x1234
        inst.src_isd = "src isd"
        inst.src_ad = "src ad"
        inst.isd_id = "target isd"
        inst.ad_id = "target ad"
        inst.version = 0x01020304
        inst.local = True
        isd_ad_obj = create_mock(["pack"])
        isd_ad_obj.pack.side_effect = (b"src ISD-AD", b"target ISD-AD")
        isd_ad.return_value = isd_ad_obj
        expected = b"".join([
            bytes.fromhex("1234"), b"src ISD-AD", b"target ISD-AD",
            bytes.fromhex("01020304"), bytes([True])])
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        isd_ad.assert_any_call("src isd", "src ad")
        isd_ad.assert_any_call("target isd", "target ad")


class TestCertChainReplyInit(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainReply.__init__
    """
    @patch("lib.packet.cert_mgmt.CertChainReply._parse", autospec=True)
    @patch("lib.packet.cert_mgmt.CertMgmtBase.__init__", autospec=True)
    def test_full(self, super_init, parse):
        inst = CertChainReply('data')
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.eq_(inst.isd_id, 0)
        ntools.eq_(inst.ad_id, 0)
        ntools.eq_(inst.version, 0)
        ntools.eq_(inst.cert_chain, b'')
        parse.assert_called_once_with(inst, 'data')


class TestCertChainReplyParse(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainReply._parse
    """
    @patch("lib.packet.cert_mgmt.ISD_AD.from_raw", new_callable=create_mock)
    @patch("lib.packet.cert_mgmt.Raw", autospec=True)
    def test(self, raw, isd_ad):
        inst = CertChainReply()
        data = MagicMock(spec_set=["pop"])
        data.pop.side_effect = ("isd_ad", bytes.fromhex('01020304'), "chain")
        raw.return_value = data
        isd_ad.return_value = "isd", "ad"
        # Call
        inst._parse('raw')
        # Tests
        raw.assert_called_once_with("raw", inst.NAME, inst.MIN_LEN,
                                    min_=True)
        ntools.eq_(inst.isd_id, "isd")
        ntools.eq_(inst.ad_id, "ad")
        ntools.eq_(inst.version, 0x01020304)
        ntools.eq_(inst.cert_chain, "chain")


class TestCertChainReplyFromValues(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainReply.from_values
    """
    def test(self):
        inst = CertChainReply.from_values("isd", "ad", "version", b'cert_chain')
        # Tests
        ntools.assert_is_instance(inst, CertChainReply)
        ntools.eq_(inst.isd_id, "isd")
        ntools.eq_(inst.ad_id, "ad")
        ntools.eq_(inst.version, "version")
        ntools.eq_(inst.cert_chain, b'cert_chain')


class TestCertChainReplyPack(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertChainReply.pack
    """
    @patch("lib.packet.cert_mgmt.ISD_AD", autospec=True)
    def test(self, isd_ad):
        inst = CertChainReply()
        inst.isd_id = "target isd"
        inst.ad_id = "target ad"
        inst.version = 0x01020304
        inst.cert_chain = b"chain"
        isd_ad_obj = create_mock(["pack"])
        isd_ad_obj.pack.return_value = b"packed isd-ad"
        isd_ad.return_value = isd_ad_obj
        expected = b"".join([
            b"packed isd-ad", bytes.fromhex("01020304"), b"chain"])
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        isd_ad.assert_any_call("target isd", "target ad")


class TestTRCReplyInit(object):
    """
    Unit tests for lib.packet.cert_mgmt.TRCReply.__init__
    """
    @patch("lib.packet.cert_mgmt.TRCReply._parse", autospec=True)
    @patch("lib.packet.cert_mgmt.CertMgmtBase.__init__", autospec=True)
    def test_full(self, super_init, parse):
        inst = TRCReply("data")
        # Tests
        super_init.assert_called_once_with(inst)
        ntools.eq_(inst.isd_id, None)
        ntools.eq_(inst.version, None)
        ntools.eq_(inst.trc, b'')
        parse.assert_called_once_with(inst, 'data')


class TestTRCReplyFromValues(object):
    """
    Unit tests for lib.packet.cert_mgmt.TRCReply.from_values
    """
    def test(self):
        inst = TRCReply.from_values("isd_id", "version", "trc")
        # Tests
        ntools.assert_is_instance(inst, TRCReply)
        ntools.eq_(inst.isd_id, "isd_id")
        ntools.eq_(inst.version, "version")
        ntools.eq_(inst.trc, "trc")


class TestTRCReplyParse(object):
    """
    Unit tests for lib.packet.cert_mgmt.TRCReply.parse
    """
    @patch("lib.packet.cert_mgmt.Raw", autospec=True)
    def test(self, raw):
        inst = TRCReply()
        data = MagicMock(spec_set=["pop"])
        data.pop.side_effect = (
            bytes.fromhex('0102 03040506'), "trc")
        raw.return_value = data
        # Call
        inst._parse('data')
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.MIN_LEN, min_=True)
        ntools.eq_(inst.isd_id, 0x0102)
        ntools.eq_(inst.version, 0x03040506)
        ntools.eq_(inst.trc, "trc")


class TestTRCReplyPack(object):
    """
    Unit tests for lib.packet.cert_mgmt.TRCReply.pack
    """
    def test(self):
        inst = TRCReply()
        inst.isd_id = 0x0102
        inst.version = 0x03040506
        inst.trc = b"trc"
        expected = b"".join([bytes.fromhex('0102 03040506'), b"trc"])
        # Call
        ntools.eq_(inst.pack(), expected)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
