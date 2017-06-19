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
:mod:`lib_packet_ext_hdr_test` --- lib.packet.ext_hdr unit tests
================================================================
"""
# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.ext_hdr import (
    ExtensionHeader,
)


# To allow testing of ExtensionHeader, despite it having abstract methods.
class ExtensionHeaderTesting(ExtensionHeader):
    def from_values(cls):
        raise NotImplementedError

    def pack(self):
        raise NotImplementedError


class TestExtensionHeaderBytesToHdrLen(object):
    """
    Unit tests for lib.packet.ext_hdr.ExtensionHeader.bytes_to_hdr_len
    """
    def _check_valid(self, count, expected):
        ntools.eq_(expected, ExtensionHeader.bytes_to_hdr_len(count))

    def _check_invalid(self, count):
        ntools.assert_raises(AssertionError,
                             ExtensionHeader.bytes_to_hdr_len, count)

    def test_valid(self):
        for count, expected in (
            (5, 1),
            (13, 2),
            (21, 3),
        ):
            yield self._check_valid, count, expected

    def test_invalid(self):
        for count in (0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 14):
            yield self._check_invalid, count


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
