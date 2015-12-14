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
:mod:`lib_packet_pcb_ext_sibra_test` --- lib.packet.pcb_ext.sibra unit tests
============================================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.pcb_ext.sibra import SibraPcbExt
from test.testcommon import create_mock


class TestSibraPcbExtParse(object):
    """
    Unit tests for lib.packet.pcb_ext.sibra.SibraPcbExt._parse
    """
    @patch("lib.packet.pcb_ext.sibra.Raw", autospec=True)
    def test(self, raw):
        inst = SibraPcbExt()
        data = create_mock(["pop"])
        data.pop.return_value = bytes(
            [0b00000100, 0b00000011, 0b00000000, 0b00000001])
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "SibraPcbExt", SibraPcbExt.LEN)
        ntools.eq_(inst.s_bw, 2**9 + 1)
        ntools.eq_(inst.e_bw, 2**16 + 1)


class TestSibraPcbExtPack(object):
    """
    Unit tests for lib.packet.pcb_ext.sibra.SibraPcbExt.pack
    """
    def test(self):
        inst = SibraPcbExt()
        inst.s_bw = 2**9 + 1
        inst.e_bw = 2**16 + 1
        expected = bytes([0b00000100, 0b00000011, 0b00000000, 0b00000001])
        # Call
        ntools.eq_(inst.pack(), expected)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
