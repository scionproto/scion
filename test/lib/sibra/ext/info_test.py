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
:mod:`info_test` --- lib.sibra.ext.info unit tests
==================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.ext.info import ResvInfoBase
from test.testcommon import create_mock


class TestResvInfoBaseParse(object):
    """
    Unit tests for lib.sibra.ext.info.ResvInfoBase._parse
    """
    @patch("lib.sibra.ext.info.BWClass", autospec=True)
    @patch("lib.sibra.ext.info.Raw", autospec=True)
    def test(self, raw, bwcls):
        inst = ResvInfoBase()
        inst.NAME = "ResvInfoBase"
        data = create_mock(["pop"])
        data.pop.side_effect = [bytes(range(4)), "fwd", "rev", 8 << 4, 7]
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        ntools.eq_(inst.exp_tick, 0x00010203)
        bwcls.assert_called_once_with("fwd", "rev")
        ntools.eq_(inst.bw, bwcls.return_value)
        ntools.eq_(inst.index, 8)
        ntools.eq_(inst.fail_hop, 7)


class TestResvInfoBasePack(object):
    """
    Unit tests for lib.sibra.ext.info.ResvInfoBase.pack
    """
    def test(self):
        inst = ResvInfoBase()
        inst.bw = create_mock(["ceil"])
        bw = create_mock(["fwd", "rev"])
        bw.fwd, bw.rev = 5, 8
        inst.bw.ceil.return_value = bw
        inst.exp_tick = 0x00010203
        inst.index = 8
        inst.fwd_dir = True
        inst.fail_hop = 7
        expected = b"".join([bytes(range(4)), bytes.fromhex("05088807")])
        # Call
        ntools.eq_(inst.pack(), expected)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
