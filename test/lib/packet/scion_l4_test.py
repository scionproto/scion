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
:mod:`lib_packet_scion_l4_test` --- lib.packet.scion_l4 unit tests
==================================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.errors import SCIONParseError
from lib.packet.scion_l4 import parse_l4_hdr
from lib.types import L4Proto
from test.testcommon import create_mock


class TestParseL4Hdr(object):
    """
    Unit tests for lib.packet.scion_l4.parse_l4_hdr
    """
    @patch("lib.packet.scion_l4.SCIONUDPHeader", autospec=True)
    def test_udp(self, udp_hdr):
        data = create_mock(["get", "pop"])
        # Call
        ntools.eq_(parse_l4_hdr(L4Proto.UDP, data, "dst addr", "src addr"),
                   udp_hdr.return_value)
        # Tests
        udp_hdr.assert_called_once_with((
            "src addr", "dst addr", data.pop.return_value))

    @patch("lib.packet.scion_l4.SCMPHeader", autospec=True)
    def test_scmp(self, scmp_hdr):
        data = create_mock(["get", "pop"])
        # Call
        ntools.eq_(parse_l4_hdr(L4Proto.SCMP, data, "dst addr", "src addr"),
                   scmp_hdr.return_value)
        # Tests
        scmp_hdr.assert_called_once_with((
            "src addr", "dst addr", data.pop.return_value))

    def test_other_l4(self):
        # Call
        ntools.eq_(parse_l4_hdr(L4Proto.TCP, "data"), None)

    def test_unknown(self):
        ntools.assert_raises(SCIONParseError, parse_l4_hdr, 99, "data")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
