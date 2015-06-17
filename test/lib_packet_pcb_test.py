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


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
