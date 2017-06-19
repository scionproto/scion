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
:mod:`lib_packet_ext_util_test` --- lib.packet.ext_util unit tests
==================================================================
"""
# Stdlib
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.ext_util import (
    parse_extensions,
)
from test.testcommon import assert_these_calls, create_mock


class TestParseExtensions(object):
    """
    Unit tests for lib.packet.ext_util.parse_extensions
    """
    @patch("lib.packet.ext_util.EXTENSION_MAP", new_callable=dict)
    @patch("lib.packet.ext_util.L4Proto.L4", new_callable=list)
    def test(self, l4_protos, ext_map):
        data = create_mock(["pop"])
        data.pop.side_effect = (
            bytes.fromhex("881103"), "ext0 data",
            bytes.fromhex("011699"), "ext1 data",
            bytes.fromhex("FF0806"), "ext1 data",
        )
        l4_protos.append(0xFF)
        ext0 = create_mock()
        ext1 = create_mock()
        ext_map[(7, 3)] = ext0
        ext_map[(1, 6)] = ext1
        # Call
        ext_hdrs, hdr_type, unknown = parse_extensions(data, 7)
        # Tests
        assert_these_calls(data.pop, (
            call(ExtensionHeader.SUBHDR_LEN),
            call(0x11 * ExtensionHeader.LINE_LEN - ExtensionHeader.SUBHDR_LEN),
            call(ExtensionHeader.SUBHDR_LEN),
            call(0x16 * ExtensionHeader.LINE_LEN - ExtensionHeader.SUBHDR_LEN),
            call(ExtensionHeader.SUBHDR_LEN),
            call(0x08 * ExtensionHeader.LINE_LEN - ExtensionHeader.SUBHDR_LEN),
        ))
        ntools.eq_(ext_hdrs, [ext0.return_value, ext1.return_value])
        ntools.eq_(hdr_type, 0xFF)
        ntools.eq_(unknown, {0x88: [1]})

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
