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
:mod:`offer_test` --- lib.sibra.ext.offer unit tests
====================================================
"""
# Stdlib
from unittest.mock import call, patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.ext.offer import OfferBlockBase
from test.testcommon import assert_these_calls, create_mock


class TestResvInfoBaseParse(object):
    """
    Unit tests for lib.sibra.ext.info.ResvInfoBase._parse
    """
    @patch("lib.sibra.ext.offer.BWClass", autospec=True)
    @patch("lib.sibra.ext.offer.Raw", autospec=True)
    def test(self, raw, bwcls):
        inst = OfferBlockBase()
        inst.NAME = "ResvInfoBase"
        inst.RESVINFO = create_mock()
        offers = []
        for i in range(4):
            offers.append("fwd %d" % i)
            offers.append("rev %d" % i)
        data = create_mock(["__bool__", "__len__", "pop"])
        data.__bool__.side_effect = ([True] * 4) + [False]
        data.pop.side_effect = ["resv info"] + offers
        data.__len__.return_value = 4 * inst.OFFER_LEN
        raw.return_value = data
        # Call
        inst._parse("data")
        # Tests
        inst.RESVINFO.assert_called_once_with("resv info")
        ntools.eq_(inst.info, inst.RESVINFO.return_value)
        ntools.eq_(inst.offer_hops, 4)
        assert_these_calls(bwcls, [
            call("fwd 0", "rev 0"), call("fwd 1", "rev 1"),
            call("fwd 2", "rev 2"), call("fwd 3", "rev 3"),
        ])


class TestResvInfoBaseFromValues(object):
    """
    Unit tests for lib.sibra.ext.info.ResvInfoBase.from_values
    """
    def test(self):
        inst = OfferBlockBase.from_values("info", 6)
        # Tests
        ntools.eq_(inst.info, "info")
        ntools.eq_(inst.offer_hops, 8)
        ntools.eq_(len(inst.offers), 8)


class TestResvInfoBasePack(object):
    """
    Unit tests for lib.sibra.ext.info.ResvInfoBase._pack
    """
    def test(self):
        inst = OfferBlockBase()
        inst.info = create_mock(["pack"])
        inst.info.pack.return_value = bytes(range(inst.LINE_LEN))
        for i in range(4):
            offer = create_mock(["fwd", "rev"])
            offer.fwd = i
            offer.rev = i * 2
            inst.offers.append(offer)
        inst.offer_hops = 4
        expected = b"".join([
            bytes(range(inst.LINE_LEN)),
            bytes.fromhex("0000 0102 0204 0306"),
        ])
        # Call
        ntools.eq_(inst.pack(), expected)


class TestResvInfoBaseGetMin(object):
    """
    Unit tests for lib.sibra.ext.info.ResvInfoBase.get_min
    """
    def test(self):
        inst = OfferBlockBase()
        inst.info = create_mock(["fail_hop"])
        inst.info.fail_hop = 2
        offer = create_mock(["min"])
        inst.offers = [offer] * 5
        # Call
        ret = inst.get_min(5)
        # Tests
        assert_these_calls(ret.min, [call(offer)] * 3)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
