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
:mod:`lib_packet_rev_info_test` --- lib.packet.rev_info tests
=============================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose.tools as ntools

# SCION
from lib.packet.rev_info import RevocationInfo
from test.testcommon import create_mock


class TestRevocationInfoParse(object):
    """
    Unit tests for lib.packet.rev_info.RevocationInfo._parse
    """
    @patch("lib.packet.rev_info.Raw", autospec=True)
    def test(self, raw):
        inst = RevocationInfo()
        data = create_mock(["pop"])
        data.pop.return_value = bytes(range(32))
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        raw.assert_called_once_with("data", "RevocationInfo", inst.LEN)
        ntools.eq_(inst.rev_token, bytes(range(32)))


class TestRevocationInfoFromValues(object):
    """
    Unit tests for lib.packet.rev_info.RevocationInfo.from_values
    """
    def test(self):
        inst = RevocationInfo.from_values("rev token")
        # Tests
        ntools.assert_is_instance(inst, RevocationInfo)
        ntools.eq_(inst.rev_token, "rev token")


class TestRevocationInfoPack(object):
    """
    Unit tests for lib.packet.rev_info.RevocationInfo.pack
    """
    def test(self):
        inst = RevocationInfo()
        inst.rev_token = bytes(range(32))
        # Call
        ntools.eq_(inst.pack(), bytes(range(32)))
