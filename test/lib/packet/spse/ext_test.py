# Copyright 2017 ETH Zurich
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
:mod:`ext_test` --- lib.packet.spse.ext.SCIONPacketSecurityExtn unit tests
==============================================================================
"""
# Stdlib
from unittest.mock import patch

import nose
import nose.tools as ntools

from lib.packet.spse.defines import (
    SPSELengths,
    SPSESecModes,
    SPSEValidationError,
)
from lib.packet.spse.ext import SCIONPacketSecurityExtn
from test.testcommon import create_mock


class TestSCIONPacketSecurityExtnParse(object):
    """
    Unit tests for lib.packet.spse.ext.SCIONPacketSecurityExtn._parse
    """
    @patch("lib.packet.spse.ext.SPSELengths", autospec=True)
    @patch("lib.packet.spse.ext.EndToEndExtension._parse", autospec=True)
    @patch("lib.packet.spse.ext.Raw", autospec=True)
    def test(self, raw, super_parse, lengths):
        inst = SCIONPacketSecurityExtn()
        inst.append_hop = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = ("sec_mode", "metadata", "authenticator")
        raw.return_value = data
        arg = bytes(21)
        # Call
        inst._parse(arg)
        # Tests
        raw.assert_called_once_with(arg, "SCIONPacketSecurityExtn")
        super_parse.assert_called_once_with(inst, data)
        ntools.assert_equal(inst.sec_mode, "sec_mode")
        ntools.assert_equal(inst.metadata, "metadata")
        ntools.assert_equal(inst.authenticator, "authenticator")


class TestSCIONPacketSecurityExtnPack(object):
    """
    Unit tests for lib.packet.spse.ext.SCIONPacketSecurityExtn.pack
    """
    def test(self):
        inst = SCIONPacketSecurityExtn.from_values(
            SPSESecModes.AES_CMAC, bytes(range(4)), bytes(range(4, 20)))
        inst._check_len = create_mock()
        expected = b"".join((
            bytes([SPSESecModes.AES_CMAC]),
            bytes(range(4)),
            bytes(range(4, 20))))
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        inst._check_len.assert_called_once_with(expected)


class TestCheckValidity(object):
    """
    Unit tests for lib.packet.spse.ext.SCIONPacketSecurityExtn.check_validity
    """
    def test(self):
        mode = SPSESecModes.AES_CMAC
        SCIONPacketSecurityExtn.check_validity(
            mode, bytes(SPSELengths.META[mode]), bytes(SPSELengths.AUTH[mode]))

    def test_invalid_sec_mode(self):
        func = SCIONPacketSecurityExtn.check_validity
        ntools.assert_raises(SPSEValidationError, func, -1, None, None)

    def test_invalid_meta_length(self):
        func = SCIONPacketSecurityExtn.check_validity
        mode = SPSESecModes.ED25519
        meta = bytes(SPSELengths.META[mode])
        auth = bytes(SPSELengths.AUTH[mode])
        ntools.assert_raises(SPSEValidationError, func, mode, meta + bytes(1), auth)

    def test_invalid_auth_length(self):
        func = SCIONPacketSecurityExtn.check_validity
        mode = SPSESecModes.ED25519
        meta = bytes(SPSELengths.META[mode])
        auth = bytes(SPSELengths.AUTH[mode])
        ntools.assert_raises(SPSEValidationError, func, mode, meta, auth + bytes(1))

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
