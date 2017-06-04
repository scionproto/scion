# Copyright 2016 ETH Zurich
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
:mod:`sof_test` --- lib.sibra.ext.sof unit tests
================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.ext.sof import SibraOpaqueField
from test.testcommon import create_mock


class TestSibraOpaqueFieldParse(object):
    """
    Unit tests for lib.sibra.ext.sof.SibraOpaqueField._parse
    """
    @patch("lib.sibra.ext.sof.Raw", autospec=True)
    def test(self, raw):
        inst = SibraOpaqueField()
        data = create_mock(["pop"])
        data.pop.side_effect = bytes(range(4)), "mac"
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", inst.NAME, inst.LEN)
        ntools.eq_(inst.ingress, 0x0001)
        ntools.eq_(inst.egress, 0x0203)
        ntools.eq_(inst.mac, "mac")


class TestSibraOpaqueFieldPack(object):
    """
    Unit tests for lib.sibra.ext.sof.SibraOpaqueField.pack
    """
    def test(self):
        inst = SibraOpaqueField()
        inst.ingress = 0x0001
        inst.egress = 0x0203
        inst.mac = b"mac"
        # Call
        ntools.eq_(inst.pack(), bytes(range(4)) + b"mac")


class TestSibraOpaqueFieldCalcMac(object):
    """
    Unit tests for lib.sibra.ext.sof.SibraOpaqueField.calc_mac
    """
    @patch("lib.sibra.ext.sof.mac", autospec=True)
    def test_steady_no_prev(self, mac):
        inst = SibraOpaqueField()
        inst.ingress = 0x1111
        inst.egress = 0xFFFF
        mac.return_value = "cmac123"
        info = create_mock(["LEN", "pack"])
        info.LEN = 8
        info.pack.return_value = b"packinfo"
        # Call
        ntools.eq_(inst.calc_mac(info, "key", [b"path id0"]), "cmac")
        # Tests
        mac.assert_called_once_with("key", b"".join([
            bytes.fromhex("1111 FFFF"), b"packinfo", b"path id0",
            bytes(inst.MAX_PATH_IDS_LEN - 8), bytes(8),
            bytes(inst.MAC_BLOCK_PADDING),
        ]))

    @patch("lib.sibra.ext.sof.mac", autospec=True)
    def test_ephemeral_prev(self, mac):
        inst = SibraOpaqueField()
        inst.ingress = 0x1111
        inst.egress = 0xFFFF
        mac.return_value = "cmac123"
        info = create_mock(["LEN", "pack"])
        info.LEN = 8
        info.pack.return_value = b"packinfo"
        path_ids = b"steadyid", b"ephemeralpath id"
        prev_raw = b"deadbeef"
        # Call
        ntools.eq_(inst.calc_mac(info, "key", path_ids, prev_raw), "cmac")
        # Tests
        mac.assert_called_once_with("key", b"".join([
            bytes.fromhex("1111 FFFF"), b"packinfo",
            b"steadyid", b"ephemeralpath id", bytes(inst.MAX_PATH_IDS_LEN - 24),
            prev_raw, bytes(inst.MAC_BLOCK_PADDING),
        ]))

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
