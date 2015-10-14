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
from lib.defines import L4_UDP
from lib.errors import SCIONParseError
from lib.packet.scion_l4 import parse_l4_hdr
from test.testcommon import create_mock


class TestParseL4Hdr(object):
    """
    Unit tests for lib.packet.scion_l4.parse_l4_hdr
    """
    @patch("lib.packet.scion_l4.SCIONUDPHeader", autospec=True)
    @patch("lib.packet.scion_l4.PayloadRaw", autospec=True)
    def test_udp(self, pld_raw, udp_hdr):
        data = create_mock(["get", "pop"])
        # Call
        ntools.eq_(parse_l4_hdr(L4_UDP, data, "src addr", "dst addr"),
                   udp_hdr.return_value)
        # Tests
        pld_raw.assert_called_once_with(data.get.return_value)
        udp_hdr.assert_called_once_with((
            "src addr", "dst addr", data.pop.return_value,
            pld_raw.return_value
        ))

    def test_unknown(self):
        ntools.assert_raises(SCIONParseError, parse_l4_hdr, 99, "data")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
