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
:mod:`path_tests` --- SCION path packet tests
=============================================
"""
#Stdlib
import copy
from unittest.mock import patch

# External packages
import nose.tools as ntools

# SCION
from lib.packet.path import (
    CorePath,
    CrossOverPath,
    PathBase,
)
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    # OpaqueFieldType,
)


class TestPathBaseInit(object):
    """
    Unit tests for lib.packet.path.PathBase.__init__
    """
    def test(self):
        """
        Tests proper member initialization.
        """
        path = PathBase()
        ntools.eq_(path.up_segment_info, None)
        ntools.eq_(path.up_segment_hops, [])
        ntools.eq_(path.down_segment_info, None)
        ntools.eq_(path.down_segment_hops, [])
        ntools.assert_false(path.parsed)


class TestPathBaseReverse(object):
    """
    Unit tests for lib.packet.path.PathBase.reverse
    """
    def test(self):
        path = PathBase()
        iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 3)
        iof2 = InfoOpaqueField.from_values(3, False, 9, 65, 5)
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        path.up_segment_info = iof1
        path.down_segment_info = iof2
        path.up_segment_hops = [hof1, hof2, hof3]
        path.down_segment_hops = [hof1, hof2, hof3, hof4, hof5]
        iof1_ = copy.copy(iof1)
        iof2_ = copy.copy(iof2)
        path.reverse()
        iof1_.up_flag ^= True
        iof2_.up_flag ^= True
        ntools.eq_(path.up_segment_info, iof2_)
        ntools.eq_(path.down_segment_info, iof1_)
        ntools.eq_(path.up_segment_hops, [hof5, hof4, hof3, hof2, hof1])
        ntools.eq_(path.down_segment_hops, [hof3, hof2, hof1])


class TestPathBaseIsLastHop(object):
    """
    Unit tests for lib.packet.path.PathBase.is_last_hop
    """
    def test(self):
        path = PathBase()
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        path.up_segment_hops = [hof1, hof2, hof3]
        path.down_segment_hops = [hof1, hof2, hof3, hof4, hof5]
        ntools.assert_true(path.is_last_hop(hof5))
        ntools.assert_false(path.is_last_hop(hof4))
        ntools.assert_false(path.is_last_hop(hof1))


class TestPathBaseIsFirstHop(object):
    """
    Unit tests for lib.packet.path.PathBase.is_first_hop
    """
    def test(self):
        path = PathBase()
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        path.up_segment_hops = [hof1, hof2, hof3]
        path.down_segment_hops = [hof1, hof2, hof3, hof4, hof5]
        ntools.assert_true(path.is_first_hop(hof1))
        ntools.assert_false(path.is_first_hop(hof2))
        ntools.assert_false(path.is_first_hop(hof5))


class TestPathBaseGetFirstHopOf(object):
    """
    Unit tests for lib.packet.path.PathBase.get_first_hop_of
    """
    def test(self):
        path = PathBase()
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        path.down_segment_hops = [hof3, hof4, hof5]
        ntools.eq_(path.get_first_hop_of(), hof3)
        path.up_segment_hops = [hof1, hof2, hof3]
        ntools.eq_(path.get_first_hop_of(), hof1)


class TestPathBaseGetOf(object):
    """
    Unit tests for lib.packet.path.PathBase.get_of
    """
    def test(self):
        path = PathBase()
        iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 3)
        iof2 = InfoOpaqueField.from_values(3, False, 9, 65, 5)
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        path.up_segment_info = iof1
        path.down_segment_info = iof2
        path.down_segment_hops = [hof3, hof4, hof5]
        path.up_segment_hops = [hof1, hof2, hof3]
        ofs = [iof1, hof1, hof2, hof3, iof2, hof3, hof4, hof5]
        for i, opaque_field in enumerate(ofs):
            ntools.eq_(path.get_of(i), opaque_field)
        ntools.eq_(path.get_of(8), None)


class TestCorePathInit(object):
    """
    Unit tests for lib.packet.path.CorePath.__init__
    """
    def test_basic(self):
        core_path = CorePath()
        ntools.eq_(core_path.up_segment_info, None)
        ntools.eq_(core_path.up_segment_hops, [])
        ntools.eq_(core_path.down_segment_info, None)
        ntools.eq_(core_path.down_segment_hops, [])
        ntools.assert_false(core_path.parsed)
        ntools.eq_(core_path.core_segment_info, None)
        ntools.eq_(core_path.core_segment_hops, [])

    @patch("lib.packet.path.CorePath.parse")
    def test_raw(self, parse):
        core_path = CorePath("data")
        parse.assert_called_once_with("data")


class TestCorePathParse(object):
    """
    Unit tests for lib.packet.path.CorePath.parse
    """
    def test(self):
        raw = b'1\x00\x00\x00-\x00\x12\x02\x00x\x00\x80\x05\x00\x1e\x03\x00'\
              b'\x8c\x00P8\x00\r\x90\x0c\x00\x00\x00\x1d\x003\x03\x00\x8c'\
              b'\x00P8\x00\r\x90\x00P\x00\xc0\x16\x00\x19:\x00\x0c\x06 \x03'\
              b'\x00\x03l\x06\x00\x00\x00\t\x00A\x02\x00P\x00\xc0\x16\x00'\
              b'\x19:\x00Z\x0e\xb07\x00\x03\x1a'
        core_path = CorePath()
        core_path.parse(raw)
        iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 2)
        iof2 = InfoOpaqueField.from_values(3, False, 9, 65, 2)
        iof3 = InfoOpaqueField.from_values(6, False, 29, 51, 3)
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        ntools.eq_(core_path.up_segment_info, iof1)
        ntools.eq_(core_path.down_segment_info, iof2)
        ntools.eq_(core_path.core_segment_info, iof3)
        ntools.eq_(core_path.up_segment_hops, [hof1, hof2])
        ntools.eq_(core_path.down_segment_hops, [hof3, hof5])
        ntools.eq_(core_path.core_segment_hops, [hof2, hof3, hof4])
        ntools.assert_true(core_path.parsed)

    def test_bad_length(self):
        raw = b'1\x00\x00\x00-\x00\x12\x02\x00x\x00\x80\x05\x00\x1e\x03\x00'\
              b'\x8c\x00P8\x00\r\x90\x0c\x00\x00\x00\x1d\x003\x03\x00\x8c'
        core_path = CorePath()
        core_path.parse(raw)
        ntools.assert_false(core_path.parsed)


class TestCorePathPack(object):
    """
    Unit tests for lib.packet.path.CorePath.pack
    """
    def test(self):
        core_path = CorePath()
        iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 2)
        iof2 = InfoOpaqueField.from_values(3, False, 9, 65, 2)
        iof3 = InfoOpaqueField.from_values(6, False, 29, 51, 3)
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        core_path.up_segment_info = iof1
        core_path.down_segment_info = iof2
        core_path.core_segment_info = iof3
        core_path.up_segment_hops = [hof1, hof2]
        core_path.down_segment_hops = [hof3, hof5]
        core_path.core_segment_hops = [hof2, hof3, hof4]
        packed = b'1\x00\x00\x00-\x00\x12\x02\x00x\x00\x80\x05\x00\x1e\x03\x00'\
              b'\x8c\x00P8\x00\r\x90\x0c\x00\x00\x00\x1d\x003\x03\x00\x8c'\
              b'\x00P8\x00\r\x90\x00P\x00\xc0\x16\x00\x19:\x00\x0c\x06 \x03'\
              b'\x00\x03l\x06\x00\x00\x00\t\x00A\x02\x00P\x00\xc0\x16\x00'\
              b'\x19:\x00Z\x0e\xb07\x00\x03\x1a'
        ntools.eq_(core_path.pack(), packed)


class TestCorePathReverse(object):
    """
    Unit tests for lib.packet.path.CorePath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse")
    def test(self, reverse):
        core_path = CorePath()
        iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 2)
        iof1_ = copy.copy(iof1)
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        core_path.core_segment_info = iof1
        core_path.core_segment_hops = [hof1, hof2, hof3]
        core_path.reverse()
        reverse.assert_called_once_with(core_path)
        ntools.eq_(core_path.core_segment_hops, [hof3, hof2, hof1])
        iof1_.up_flag ^= True
        ntools.eq_(core_path.core_segment_info, iof1_)


class TestCorePathReverse(object):
    """
    Unit tests for lib.packet.path.CorePath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse")
    def test(self, reverse):
        core_path = CorePath()
        iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 2)
        iof1_ = copy.copy(iof1)
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        core_path.core_segment_info = iof1
        core_path.core_segment_hops = [hof1, hof2, hof3]
        core_path.reverse()
        reverse.assert_called_once_with(core_path)
        ntools.eq_(core_path.core_segment_hops, [hof3, hof2, hof1])
        iof1_.up_flag ^= True
        ntools.eq_(core_path.core_segment_info, iof1_)


class TestCorePathGetOf(object):
    """
    Unit tests for lib.packet.path.CorePath.get_of
    """
    def test(self):
        core_path = CorePath()
        iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 2)
        iof2 = InfoOpaqueField.from_values(3, False, 9, 65, 2)
        iof3 = InfoOpaqueField.from_values(6, False, 29, 51, 3)
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        core_path.up_segment_info = iof1
        core_path.down_segment_info = iof2
        core_path.core_segment_info = iof3
        core_path.up_segment_hops = [hof1, hof2]
        core_path.down_segment_hops = [hof3, hof5]
        core_path.core_segment_hops = [hof2, hof3, hof4]
        ofs = [iof1, hof1, hof2, iof3, hof2, hof3, hof4, iof2, hof3, hof5]
        for i, opaque_field in enumerate(ofs):
            ntools.eq_(core_path.get_of(i), opaque_field)
        ntools.eq_(core_path.get_of(10), None)


class TestCorePathFromValues(object):
    """
    Unit tests for lib.packet.path.CorePath.from_values
    """
    def test(self):
        iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 2)
        iof2 = InfoOpaqueField.from_values(3, False, 9, 65, 2)
        iof3 = InfoOpaqueField.from_values(6, False, 29, 51, 3)
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        core_path = CorePath.from_values(iof1, [hof1, hof2], 
                                         iof2, [hof2, hof3, hof4], 
                                         iof3, [hof3, hof5])
        ntools.eq_(core_path.up_segment_info, iof1)
        ntools.eq_(core_path.core_segment_info, iof2)
        ntools.eq_(core_path.down_segment_info, iof3)
        ntools.eq_(core_path.up_segment_hops, [hof1, hof2])
        ntools.eq_(core_path.core_segment_hops, [hof2, hof3, hof4])
        ntools.eq_(core_path.down_segment_hops, [hof3, hof5])


class TestCorePathFromValues(object):
    """
    Unit tests for lib.packet.path.CorePath.from_values
    """
    def test(self):
        iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 2)
        iof2 = InfoOpaqueField.from_values(3, False, 9, 65, 2)
        iof3 = InfoOpaqueField.from_values(6, False, 29, 51, 3)
        hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        hof5 = HopOpaqueField.from_values(90, 235, 55, 794)
        core_path = CorePath.from_values(iof1, [hof1, hof2], 
                                         iof2, [hof2, hof3, hof4], 
                                         iof3, [hof3, hof5])
        ntools.eq_(core_path.up_segment_info, iof1)
        ntools.eq_(core_path.core_segment_info, iof2)
        ntools.eq_(core_path.down_segment_info, iof3)
        ntools.eq_(core_path.up_segment_hops, [hof1, hof2])
        ntools.eq_(core_path.core_segment_hops, [hof2, hof3, hof4])
        ntools.eq_(core_path.down_segment_hops, [hof3, hof5])


class TestCorePathStr(object):
    """
    Unit tests for lib.packet.path.CorePath.__str__
    """
    def test(self):
        pass


class TestCrossOverPathInit(object):
    """
    Unit tests for lib.packet.path.CrossOverPath.__init__
    """
    @patch("lib.packet.path.PathBase.__init__")
    def test_basic(self, __init__):
        co_path = CrossOverPath()
        __init__.assert_called_once_with(co_path)
        ntools.eq_(co_path.up_segment_upstream_ad, None)
        ntools.eq_(co_path.down_segment_upstream_ad, None)

    @patch("lib.packet.path.CrossOverPath.parse")
    def test_raw(self, parse):
        co_path = CrossOverPath("data")
        parse.assert_called_once_with("data")


if __name__ == "__main__":
    nose.run(defaultTest=__name__)