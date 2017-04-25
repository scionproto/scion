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
:mod:`lib_packet_base_test` --- Packet base class tests
=======================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.packet.pcb import (
    Marking,
    PCBMarking,
)


class TestMarkingInit(object):
    """
    Unit test for lib.packet.pcb.Marking.__init__
    """
    def test(self):
        marking = Marking()
        ntools.assert_false(marking.parsed)
        ntools.assert_is_none(marking.raw)


class TestMarkingEq(object):
    """
    Unit test for lib.packet.pcb.Marking.__eq__
    """
    def test_same_type(self):
        marking1 = Marking()
        marking2 = Marking()
        marking1.raw = 'rawstring'
        marking2.raw = 'rawstring'
        ntools.eq_(marking1, marking2)

    def test_diff_type(self):
        marking1 = Marking()
        marking2 = 123
        ntools.assert_not_equals(marking1, marking2)


class TestPCBMarkingInit(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.__init__
    """
    @patch("lib.packet.pcb.Marking.__init__")
    def test_basic(self, __init__):
        pcbm = PCBMarking()
        __init__.assert_called_once_with(pcbm)
        ntools.eq_(pcbm.isd_id, 0)
        ntools.eq_(pcbm.ad_id, 0)
        ntools.assert_is_none(pcbm.hof)
        ntools.eq_(pcbm.ig_rev_token, 32 * b"\x00")
        ntools.eq_(pcbm.eg_rev_token, 32 * b"\x00")

    @patch("lib.packet.pcb.PCBMarking.parse")
    def test_raw(self, parse):
        pcbm = PCBMarking('rawstring')
        parse.assert_called_once_with('rawstring')


class TestPCBMarkingParse(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.parse
    """
    def test(self):
        pass


class TestPCBMarkingFromValues(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.from_values
    """
    def test(self):
        pcbm = PCBMarking.from_values(1, 2, 3, 4, 5)
        ntools.eq_(pcbm.isd_id, 1)
        ntools.eq_(pcbm.ad_id, 2)
        ntools.eq_(pcbm.hof, 3)
        ntools.eq_(pcbm.ig_rev_token, 4)
        ntools.eq_(pcbm.eg_rev_token, 5)


class TestPCBMarkingPack(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.pack
    """
    def test(self):
        pass


class TestPCBMarkingEq(object):
    """
    Unit test for lib.packet.pcb.PCBMarking.__eq__
    """
    def test_same_type(self):
        pcbm1 = PCBMarking.from_values(1, 2, 3, 4, 5)
        pcbm2 = PCBMarking.from_values(1, 2, 3, 4, 5)
        ntools.eq_(pcbm1, pcbm2)

    def test_diff_type(self):
        pcbm1 = PCBMarking()
        pcbm2 = 123
        ntools.assert_not_equals(pcbm1, pcbm2)


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
