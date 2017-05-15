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
:mod:`extn_test` --- lib.packet.spse.scmp_auth.extn unit tests
==============================================================================
"""
# Stdlib
from unittest.mock import patch

import nose
import nose.tools as ntools

from lib.packet.spse.defines import SPSESecModes, SPSEValidationError
from lib.packet.spse.scmp_auth.ext_drkey import Lengths, SCMPAuthDRKeyExtn
from test.testcommon import create_mock


class TestSCMPAuthDRKeyExtnParse(object):
    """
    Unit tests for lib.packet.spse.scmp_auth.extn.SCMPAuthDRKeyExtn._parse
    """
    @patch("lib.packet.spse.scmp_auth.ext_drkey."
           "SCIONPacketSecurityBaseExtn._parse", autospec=True)
    @patch("lib.packet.spse.scmp_auth.ext_drkey.Raw", autospec=True)
    def test(self, raw, super_parse):
        inst = SCMPAuthDRKeyExtn()
        inst.append_hop = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = ("sec_mode", "direction", "padding", "mac")
        raw.return_value = data
        arg = bytes(21)
        # Call
        inst._parse(arg)
        # Tests
        raw.assert_called_once_with(arg, "SCMPAuthDRKeyExtn")
        super_parse.assert_called_once_with(inst, data)
        ntools.assert_equal(inst.sec_mode, "sec_mode")
        ntools.assert_equal(inst.direction, "direction")
        ntools.assert_equal(inst.mac, "mac")


class TestSCMPAuthDRKeyExtnPack(object):
    """
    Unit tests for lib.packet.spse.scmp_auth.extn.SCMPAuthDRKeyExtn.pack
    """
    def test(self):
        inst = SCMPAuthDRKeyExtn.from_values(2, bytes(range(16)))
        inst._check_len = create_mock()
        expected = b"".join((
            bytes([SPSESecModes.SCMP_AUTH_DRKEY]),
            bytes((2,)),
            bytes(3),
            bytes(range(16))))
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        inst._check_len.assert_called_once_with(expected)


class TestSCMPAuthDRKeyCheckValidity(object):
    """
    Unit tests for lib.packet.spse.scmp_auth.extn.SCMPAuthDRKeyExtn.check_validity
    """
    def test(self):
        func = SCMPAuthDRKeyExtn.check_validity
        mac = bytes(Lengths.MAC)
        for dir in range(6):
            func(dir, mac)
        ntools.assert_raises(SPSEValidationError, func, 7, mac)
        ntools.assert_raises(SPSEValidationError, func, -1, mac)
        ntools.assert_raises(SPSEValidationError, func, 0, mac + bytes(1))


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
