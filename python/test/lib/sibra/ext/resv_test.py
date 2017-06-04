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
:mod:`resv_test` --- lib.sibra.ext.resv unit tests
==================================================
"""
# Stdlib
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.ext.resv import ResvBlockBase
from lib.sibra.ext.sof import SibraOpaqueField
from test.testcommon import assert_these_calls, create_mock


class TestResvBlockBaseParse(object):
    """
    Unit tests for lib.sibra.ext.resv.ResvBlockBase._parse
    """
    @patch("lib.sibra.ext.resv.SibraOpaqueField", autospec=True)
    @patch("lib.sibra.ext.resv.Raw", autospec=True)
    def test(self, raw, sof):
        inst = ResvBlockBase()
        inst.NAME = "ResvBlockBase"
        inst.RESVINFO = create_mock(["LEN"])
        inst.RESVINFO.LEN = 8
        sof.LEN = 8
        hops = []
        for i in range(4):
            hops.append("hop %d" % i)
        hops.append(bytes(8))
        data = create_mock(["__bool__", "__len__", "pop"])
        data.__bool__.side_effect = ([True] * 5) + [False]
        data.pop.side_effect = ["resv info"] + hops
        data.__len__.return_value = 5 * 8
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        inst.RESVINFO.assert_called_once_with("resv info")
        ntools.eq_(inst.info, inst.RESVINFO.return_value)
        ntools.eq_(inst.num_hops, 5)
        assert_these_calls(sof, [call(hop) for hop in hops[:-1]])
        ntools.eq_(inst.sofs, [sof.return_value] * 4)


class TestResvBlockBasePack(object):
    """
    Unit tests for lib.sibra.ext.resv.ResvBlockBase.pack
    """
    def test(self):
        inst = ResvBlockBase()
        inst.num_hops = 5
        inst.info = create_mock(["pack"])
        inst.info.pack.return_value = b"resv info"
        for i in range(2):
            sof = create_mock(["pack"])
            sof.pack.return_value = ("sof %d" % i).encode("ascii")
            inst.sofs.append(sof)
        expected = b"".join([b"resv info", b"sof 0", b"sof 1",
                             bytes(SibraOpaqueField.LEN * 3)])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestResvBlockBaseAddHop(object):
    """
    Unit tests for lib.sibra.ext.resv.ResvBlockBase.add_hop
    """
    @patch("lib.sibra.ext.resv.SibraOpaqueField", autospec=True)
    def test(self, sof):
        inst = ResvBlockBase()
        inst.info = "info"
        inst.num_hops = 4
        # Call
        inst.add_hop("ingress", "egress", "prev_raw", "key", "path ids")
        # Tests
        sof.from_values.assert_called_once_with("ingress", "egress")
        inst.sofs[0].calc_mac.assert_called_once_with(
            "info", "key", "path ids", "prev_raw")
        ntools.eq_(inst.sofs[0].mac, inst.sofs[0].calc_mac.return_value)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
