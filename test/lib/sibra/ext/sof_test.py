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
from lib.sibra.ext.sof import SibraHopOpaqueField
from test.testcommon import create_mock


class TestSibraHopOpaqueFieldCalcMac(object):
    """
    Unit tests for lib.sibra.ext.sof.SibraHopOpaqueField.calc_mac
    """
    @patch("lib.sibra.ext.sof.cbcmac", autospec=True)
    def test_steady_no_prev(self, cbcmac):
        inst = SibraHopOpaqueField()
        inst.pack = create_mock()
        inst.pack.return_value = b"ITifsMAC"
        cbcmac.return_value = "cbcmac"
        info = create_mock(["LEN", "pack"])
        info.LEN = 8
        info.pack.return_value = b"packinfo"
        # Call
        ntools.eq_(inst.calc_mac(info, "key", [b"path id0"]), "cbc")
        # Tests
        cbcmac.assert_called_once_with("key", b"".join([
            b"Tifs", b"packinfo", b"path id0",
            bytes(inst.MAX_PATH_IDS_LEN - 8), bytes(7),
            bytes(inst.MAC_BLOCK_PADDING),
        ]))

    @patch("lib.sibra.ext.sof.cbcmac", autospec=True)
    def test_ephemeral_prev(self, cbcmac):
        inst = SibraHopOpaqueField()
        inst.pack = create_mock()
        inst.pack.return_value = b"ITifsMAC"
        cbcmac.return_value = "cbcmac"
        info = create_mock(["LEN", "pack"])
        info.LEN = 8
        info.pack.return_value = b"packinfo"
        path_ids = b"steadyid", b"ephemeralpath id"
        prev_raw = b"deadbeef"
        # Call
        ntools.eq_(inst.calc_mac(info, "key", path_ids, prev_raw), "cbc")
        # Tests
        cbcmac.assert_called_once_with("key", b"".join([
            b"Tifs", b"packinfo", b"steadyid", b"ephemeralpath id",
            bytes(inst.MAX_PATH_IDS_LEN - 24), prev_raw[1:],
            bytes(inst.MAC_BLOCK_PADDING),
        ]))

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
