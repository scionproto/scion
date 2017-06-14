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

from lib.packet.opt.defines import (
    OPTLengths,
    # OPTBaseError,
    OPTValidationError)
from lib.packet.opt.ext import SCIONOriginPathTraceExtn
from test.testcommon import create_mock


class TestSCIONPacketSecurityExtnParse(object):
    """
    Unit tests for lib.packet.opt.ext.SCIONOriginPathTraceExtn._parse
    """
    @patch("lib.packet.opt.ext.OPTLengths", autospec=True)
    @patch("lib.packet.opt.ext.EndToEndExtension._parse", autospec=True)
    @patch("lib.packet.opt.ext.Raw", autospec=True)
    def test(self, raw, super_parse, lengths):
        inst = SCIONOriginPathTraceExtn()
        inst.append_hop = create_mock()
        data = create_mock(["pop"])
        data.pop.side_effect = ("datahash", "sessionID", "PVF")
        raw.return_value = data
        arg = bytes(16+16+16)
        # Call
        inst._parse(arg)
        # Tests
        raw.assert_called_once_with(arg, "SCIONOriginPathTraceExtn")
        super_parse.assert_called_once_with(inst, data)
        ntools.assert_equal(inst.datahash, "datahash")
        ntools.assert_equal(inst.sessionID, "sessionID")
        ntools.assert_equal(inst.PVF, "PVF")


class TestSCIONOriginPathTraceExtnPack(object):
    """
    Unit tests for lib.packet.opt.ext.SCIONOriginPathTraceExtn.pack
    """
    def test(self):
        inst = SCIONOriginPathTraceExtn.from_values(
            bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 48)))
        inst._check_len = create_mock()
        expected = b"".join((
            bytes(range(16)),
            bytes(range(16, 32)),
            bytes(range(32, 48))))
        # Call
        ntools.eq_(inst.pack(), expected)
        # Tests
        inst._check_len.assert_called_once_with(expected)


class TestCheckValidity(object):
    """
    Unit tests for lib.packet.opt.ext.SCIONOriginPathTraceExtn.check_validity
    """
    def test(self):
        SCIONOriginPathTraceExtn.check_validity(
            bytes(OPTLengths.DATAHASH), bytes(OPTLengths.SESSIONID), bytes(OPTLengths.PVF))

    def test_invalid_datahash_length(self):
        func = SCIONOriginPathTraceExtn.check_validity
        datahash = bytes(1)
        ntools.assert_raises(OPTValidationError, func, datahash, None, None)

    def test_invalid_sessionID_length(self):
        func = SCIONOriginPathTraceExtn.check_validity
        datahash = bytes(OPTLengths.DATAHASH)
        sessionID = bytes(OPTLengths.SESSIONID)
        PVF = bytes(OPTLengths.PVF)
        ntools.assert_raises(OPTValidationError, func, datahash, sessionID + bytes(1), PVF)

    def test_invalid_PVF_length(self):
        func = SCIONOriginPathTraceExtn.check_validity
        datahash = bytes(OPTLengths.DATAHASH)
        sessionID = bytes(OPTLengths.SESSIONID)
        PVF = bytes(OPTLengths.PVF)
        ntools.assert_raises(OPTValidationError, func, datahash, sessionID, PVF + bytes(1))


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
