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
import nose
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
)

class BasePath(object):
    def setup(self):
        self.path = PathBase()
        self.core_path = CorePath()
        self.iof1 = InfoOpaqueField.from_values(24, True, 45, 18, 3)
        self.iof2 = InfoOpaqueField.from_values(3, False, 9, 65, 5)
        self.iof3 = InfoOpaqueField.from_values(6, False, 29, 51, 3)
        self.hof1 = HopOpaqueField.from_values(120, 8, 5, 7683)
        self.hof2 = HopOpaqueField.from_values(140, 5, 56, 3472)
        self.hof3 = HopOpaqueField.from_values(80, 12, 22, 6458)
        self.hof4 = HopOpaqueField.from_values(12, 98, 3, 876)
        self.hof5 = HopOpaqueField.from_values(90, 235, 55, 794)

    def teardown(self):
        self.path = None
        self.iof1 = None
        self.iof2 = None
        self.iof3 = None
        self.hof1 = None
        self.hof2 = None
        self.hof3 = None
        self.hof4 = None
        self.hof5 = None
        self.core_path = None

class TestPathBaseInit(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.__init__
    """
    def test(self):
        """
        Tests proper member initialization.
        """
        ntools.eq_(self.path.up_segment_info, None)
        ntools.eq_(self.path.up_segment_hops, [])
        ntools.eq_(self.path.down_segment_info, None)
        ntools.eq_(self.path.down_segment_hops, [])
        ntools.assert_false(self.path.parsed)


class TestPathBaseReverse(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.reverse
    """
    def test(self):
        self.path.up_segment_info = self.iof1
        self.path.down_segment_info = self.iof2
        self.path.up_segment_hops = [self.hof1, self.hof2, self.hof3]
        self.path.down_segment_hops = [self.hof1, self.hof2, self.hof3, self.hof4, self.hof5]
        iof1_ = copy.copy(self.iof1)
        iof2_ = copy.copy(self.iof2)
        self.path.reverse()
        iof1_.up_flag ^= True
        iof2_.up_flag ^= True
        ntools.eq_(self.path.up_segment_info, iof2_)
        ntools.eq_(self.path.down_segment_info, iof1_)
        ntools.eq_(self.path.up_segment_hops, [self.hof5, self.hof4, self.hof3, self.hof2, self.hof1])
        ntools.eq_(self.path.down_segment_hops, [self.hof3, self.hof2, self.hof1])


class TestPathBaseIsLastHop(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.is_last_hop
    """
    def test(self):
        self.path.up_segment_hops = [self.hof1, self.hof2, self.hof3]
        self.path.down_segment_hops = [self.hof1, self.hof2, self.hof3, self.hof4, self.hof5]
        ntools.assert_true(self.path.is_last_hop(self.hof5))
        ntools.assert_false(self.path.is_last_hop(self.hof4))
        ntools.assert_false(self.path.is_last_hop(self.hof1))


class TestPathBaseIsFirstHop(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.is_first_hop
    """
    def test(self):
        self.path.up_segment_hops = [self.hof1, self.hof2, self.hof3]
        self.path.down_segment_hops = [self.hof1, self.hof2, self.hof3, self.hof4, self.hof5]
        ntools.assert_true(self.path.is_first_hop(self.hof1))
        ntools.assert_false(self.path.is_first_hop(self.hof2))
        ntools.assert_false(self.path.is_first_hop(self.hof5))


class TestPathBaseGetFirstHopOf(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.get_first_hop_of
    """
    def test(self):
        self.path.down_segment_hops = [self.hof3, self.hof4, self.hof5]
        ntools.eq_(self.path.get_first_hop_of(), self.hof3)
        self.path.up_segment_hops = [self.hof1, self.hof2, self.hof3]
        ntools.eq_(self.path.get_first_hop_of(), self.hof1)


class TestPathBaseGetOf(BasePath):
    """
    Unit tests for lib.packet.path.PathBase.get_of
    """
    def test(self):
        self.path.up_segment_info = self.iof1
        self.path.down_segment_info = self.iof2
        self.path.down_segment_hops = [self.hof3, self.hof4, self.hof5]
        self.path.up_segment_hops = [self.hof1, self.hof2, self.hof3]
        ofs = [self.iof1, self.hof1, self.hof2, self.hof3, self.iof2, self.hof3, self.hof4, self.hof5]
        for i, opaque_field in enumerate(ofs):
            ntools.eq_(self.path.get_of(i), opaque_field)
        ntools.eq_(self.path.get_of(8), None)


class TestCorePathInit(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.__init__
    """
    def test_basic(self):
        ntools.eq_(self.core_path.up_segment_info, None)
        ntools.eq_(self.core_path.up_segment_hops, [])
        ntools.eq_(self.core_path.down_segment_info, None)
        ntools.eq_(self.core_path.down_segment_hops, [])
        ntools.assert_false(self.core_path.parsed)
        ntools.eq_(self.core_path.core_segment_info, None)
        ntools.eq_(self.core_path.core_segment_hops, [])

    @patch("lib.packet.path.CorePath.parse")
    def test_raw(self, parse):
        self.core_path = CorePath("data")
        parse.assert_called_once_with("data")


class TestCorePathParse(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.parse
    """
    def test(self):
        raw = b'1\x00\x00\x00-\x00\x12\x02\x00x\x00\x80\x05\x00\x1e\x03\x00'\
              b'\x8c\x00P8\x00\r\x90\x0c\x00\x00\x00\x1d\x003\x03\x00\x8c'\
              b'\x00P8\x00\r\x90\x00P\x00\xc0\x16\x00\x19:\x00\x0c\x06 \x03'\
              b'\x00\x03l\x06\x00\x00\x00\t\x00A\x02\x00P\x00\xc0\x16\x00'\
              b'\x19:\x00Z\x0e\xb07\x00\x03\x1a'
        self.core_path.parse(raw)
        ntools.eq_(self.core_path.up_segment_info, self.iof1)
        ntools.eq_(self.core_path.down_segment_info, self.iof2)
        ntools.eq_(self.core_path.core_segment_info, self.iof3)
        ntools.eq_(self.core_path.up_segment_hops, [self.hof1, self.hof2])
        ntools.eq_(self.core_path.down_segment_hops, [self.hof3, self.hof5])
        ntools.eq_(self.core_path.core_segment_hops, [self.hof2, self.hof3, self.hof4])
        ntools.assert_true(self.core_path.parsed)

    def test_bad_length(self):
        raw = b'1\x00\x00\x00-\x00\x12\x02\x00x\x00\x80\x05\x00\x1e\x03\x00'\
              b'\x8c\x00P8\x00\r\x90\x0c\x00\x00\x00\x1d\x003\x03\x00\x8c'
        self.core_path = CorePath()
        self.core_path.parse(raw)
        ntools.assert_false(self.core_path.parsed)


class TestCorePathPack(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.pack
    """
    def test(self):
        self.core_path.up_segment_info = self.iof1
        self.core_path.down_segment_info = self.iof2
        self.core_path.core_segment_info = self.iof3
        self.core_path.up_segment_hops = [self.hof1, self.hof2]
        self.core_path.down_segment_hops = [self.hof3, self.hof5]
        self.core_path.core_segment_hops = [self.hof2, self.hof3, self.hof4]
        packed = b'1\x00\x00\x00-\x00\x12\x02\x00x\x00\x80\x05\x00\x1e\x03\x00'\
              b'\x8c\x00P8\x00\r\x90\x0c\x00\x00\x00\x1d\x003\x03\x00\x8c'\
              b'\x00P8\x00\r\x90\x00P\x00\xc0\x16\x00\x19:\x00\x0c\x06 \x03'\
              b'\x00\x03l\x06\x00\x00\x00\t\x00A\x02\x00P\x00\xc0\x16\x00'\
              b'\x19:\x00Z\x0e\xb07\x00\x03\x1a'
        ntools.eq_(self.core_path.pack(), packed)


class TestCorePathReverse(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse")
    def test(self, reverse):
        iof1_ = copy.copy(self.iof1)
        self.core_path.core_segment_info = self.iof1
        self.core_path.core_segment_hops = [self.hof1, self.hof2, self.hof3]
        self.core_path.reverse()
        reverse.assert_called_once_with(self.core_path)
        ntools.eq_(self.core_path.core_segment_hops, [self.hof3, self.hof2, self.hof1])
        iof1_.up_flag ^= True
        ntools.eq_(self.core_path.core_segment_info, iof1_)


class TestCorePathReverse(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.reverse
    """
    @patch("lib.packet.path.PathBase.reverse")
    def test(self, reverse):
        iof1_ = copy.copy(self.iof1)
        self.core_path.core_segment_info = self.iof1
        self.core_path.core_segment_hops = [self.hof1, self.hof2, self.hof3]
        self.core_path.reverse()
        reverse.assert_called_once_with(self.core_path)
        ntools.eq_(self.core_path.core_segment_hops, [self.hof3, self.hof2, self.hof1])
        iof1_.up_flag ^= True
        ntools.eq_(self.core_path.core_segment_info, iof1_)


class TestCorePathGetOf(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.get_of
    """
    def test(self):
        self.core_path.up_segment_info = self.iof1
        self.core_path.down_segment_info = self.iof2
        self.core_path.core_segment_info = self.iof3
        self.core_path.up_segment_hops = [self.hof1, self.hof2]
        self.core_path.down_segment_hops = [self.hof3, self.hof5]
        self.core_path.core_segment_hops = [self.hof2, self.hof3, self.hof4]
        ofs = [self.iof1, self.hof1, self.hof2, self.iof3, self.hof2, self.hof3, self.hof4, self.iof2, self.hof3, self.hof5]
        for i, opaque_field in enumerate(ofs):
            ntools.eq_(self.core_path.get_of(i), opaque_field)
        ntools.eq_(self.core_path.get_of(10), None)


class TestCorePathFromValues(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.from_values
    """
    def test(self):
        self.core_path = CorePath.from_values(self.iof1, [self.hof1, self.hof2],
                                         self.iof2, [self.hof2, self.hof3, self.hof4], 
                                         self.iof3, [self.hof3, self.hof5])
        ntools.eq_(self.core_path.up_segment_info, self.iof1)
        ntools.eq_(self.core_path.core_segment_info, self.iof2)
        ntools.eq_(self.core_path.down_segment_info, self.iof3)
        ntools.eq_(self.core_path.up_segment_hops, [self.hof1, self.hof2])
        ntools.eq_(self.core_path.core_segment_hops, [self.hof2, self.hof3, self.hof4])
        ntools.eq_(self.core_path.down_segment_hops, [self.hof3, self.hof5])


class TestCorePathFromValues(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.from_values
    """
    def test(self):
        self.core_path = CorePath.from_values(self.iof1, [self.hof1, self.hof2],
                                         self.iof2, [self.hof2, self.hof3, self.hof4], 
                                         self.iof3, [self.hof3, self.hof5])
        ntools.eq_(self.core_path.up_segment_info, self.iof1)
        ntools.eq_(self.core_path.core_segment_info, self.iof2)
        ntools.eq_(self.core_path.down_segment_info, self.iof3)
        ntools.eq_(self.core_path.up_segment_hops, [self.hof1, self.hof2])
        ntools.eq_(self.core_path.core_segment_hops, [self.hof2, self.hof3, self.hof4])
        ntools.eq_(self.core_path.down_segment_hops, [self.hof3, self.hof5])


class TestCorePathStr(BasePath):
    """
    Unit tests for lib.packet.path.CorePath.__str__
    """
    def test(self):
        pass


class TestCrossOverPathInit(BasePath):
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