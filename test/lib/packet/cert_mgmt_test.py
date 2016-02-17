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
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.cert_mgmt import (
    CertChainRequest,
    _TYPE_MAP,
    parse_certmgmt_payload,
)
from test.testcommon import create_mock


class TestCertMgmtRequestParse(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertMgmtRequest._parse
    """
    @patch("lib.packet.cert_mgmt.ISD_AS", autospec=True)
    @patch("lib.packet.cert_mgmt.Raw", autospec=True)
    def test(self, raw, isd_as):
        inst = CertChainRequest()
        data = create_mock(["pop"])
        data.pop.side_effect = ("ISD-AS", bytes.fromhex("01020304"))
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        isd_as.assert_called_once_with("ISD-AS")
        ntools.eq_(inst.isd_as, isd_as.return_value)
        ntools.eq_(inst.version, 0x01020304)


class TestCertMgmtRequestPack(object):
    """
    Unit tests for lib.packet.cert_mgmt.CertMgmtRequest.pack
    """
    def test(self):
        inst = CertChainRequest()
        inst.isd_as = create_mock(["pack"])
        inst.isd_as.pack.return_value = b"ISD-AS"
        inst.version = 0x01020304
        expected = b"".join([b"ISD-AS", bytes.fromhex("01020304")])
        # Call
        ntools.eq_(inst.pack(), expected)


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
