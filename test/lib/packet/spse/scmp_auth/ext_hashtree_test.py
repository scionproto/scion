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
from lib.packet.spse.scmp_auth.ext_hashtree import SCMPAuthHashtreeLengths, SCMPAuthHashTreeExtn
from test.testcommon import create_mock


class TestSCMPAuthHashTreeExtnParse(object):
    """
    Unit tests for lib.packet.spse.scmp_auth.extn.SCMPAuthHashTreeExtn._parse
    """
    @patch("lib.packet.spse.scmp_auth.ext_hashtree."
           "SCIONPacketSecurityBaseExtn._parse", autospec=True)
    @patch("lib.packet.spse.scmp_auth.ext_hashtree.Raw", autospec=True)
    def test(self, raw, super_parse):
        inst = SCMPAuthHashTreeExtn()
        inst.append_hop = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = ("sec_mode", "height", "res", "order", "sign", "hashes")
        raw.return_value = data
        arg = bytes(21)
        # Call
        inst._parse(arg)
        # Tests
        raw.assert_called_once_with(arg, "SCMPAuthHashTreeExtn")
        super_parse.assert_called_once_with(inst, data)
        ntools.assert_equal(inst.sec_mode, "sec_mode")
        ntools.assert_equal(inst.height, "height")
        ntools.assert_equal(inst.order, "order")
        ntools.assert_equal(inst.signature, "sign")
        ntools.assert_equal(inst.hashes, "hashes")


class TestSCMPAuthHashTreeExtnPack(object):
    """
    Unit tests for lib.packet.spse.scmp_auth.extn.SCMPAuthHashTreeExtn.pack
    """
    def test(self):
        height = 2
        order = bytes(range(SCMPAuthHashtreeLengths.ORDER))
        signature = bytes(range(SCMPAuthHashtreeLengths.SIGNATURE))
        hashes = bytes(range(height * SCMPAuthHashtreeLengths.HASH))

        inst = SCMPAuthHashTreeExtn.from_values(
            height, order, signature, hashes)
        inst._check_len = create_mock()
        expected = b"".join((
            bytes([SPSESecModes.SCMP_AUTH_HASH_TREE]), bytes((height,)), bytes(1),
            order, signature, hashes))
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        inst._check_len.assert_called_once_with(expected)


class TestSCMPAuthDRKeyCheckValidity(object):
    """
    Unit tests for lib.packet.spse.scmp_auth.extn.SCMPAuthDRKeyExtn.check_validity
    """
    def _setup(self):
        return (13, bytes(SCMPAuthHashtreeLengths.ORDER), bytes(SCMPAuthHashtreeLengths.SIGNATURE),
                bytes(SCMPAuthHashtreeLengths.HASH * 13))

    def test(self):
        height, order, signature, hashes = self._setup()
        SCMPAuthHashTreeExtn.check_validity(height, order, signature, hashes)

    def test_invalid_order_length(self):
        height, order, signature, hashes = self._setup()
        func = SCMPAuthHashTreeExtn.check_validity
        ntools.assert_raises(SPSEValidationError, func, height, order + bytes(1), signature, hashes)

    def test_invalid_signature_length(self):
        height, order, signature, hashes = self._setup()
        func = SCMPAuthHashTreeExtn.check_validity
        ntools.assert_raises(SPSEValidationError, func, height, order, signature + bytes(1), hashes)

    def test_invalid_hashes_length(self):
        height, order, signature, hashes = self._setup()
        func = SCMPAuthHashTreeExtn.check_validity
        ntools.assert_raises(SPSEValidationError, func, height, order, signature, hashes + bytes(1))

    def test_invalid_height(self):
        height, order, signature, hashes = self._setup()
        func = SCMPAuthHashTreeExtn.check_validity
        ntools.assert_raises(SPSEValidationError, func, -1, order, signature, hashes)
        ntools.assert_raises(SPSEValidationError, func, 17, order, signature, hashes)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
