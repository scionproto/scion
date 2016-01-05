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
:mod:`util_test` --- lib.sibra.util unit tests
=====================================================
"""

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.util import (
    class_to_bps,
    bps_to_class,
)


class TestClassToBps(object):
    """
    Unit tests for lib.sibra.util.class_to_bps
    """
    def _check(self, bw_cls, exp_kibitps):
        ntools.assert_almost_equal(
            class_to_bps(bw_cls)/1024, exp_kibitps, places=2)

    def test_steady(self):
        for bw_cls, expected in (
            (0, 0), (1, 16), (2, 22.63), (3, 32), (4, 45.25),
        ):
            yield self._check, bw_cls, expected


class TestBpsToClass(object):
    """
    Unit tests for lib.sibra.util.bps_to_class
    """
    def _check(self, bps, expected):
        ntools.assert_almost_equal(bps_to_class(bps),
                                   expected, places=2)

    def _check_floor(self, bps, expected):
        ntools.eq_(bps_to_class(bps, floor=True), expected)

    def test(self):
        for bps, exp, exp_floor in (
            (0, 0, 0), (1, 1, 0), (2, 1, 0), (15, 1, 0), (16, 1, 1),
            (17, 1.17, 1), (22, 1.92, 1), (23, 2.05, 2),
            (31, 2.91, 2), (32, 3, 3), (33, 3.09, 3),
        ):
            yield self._check, bps * 1024, exp
            yield self._check_floor, bps * 1024, exp_floor


class TestBpsClassConverstions(object):
    """
    Tests for lib.sibra.util's class_to_bps and bps_to_class
    """
    def _check_bps_class_bps(self, bps, expected):
        ntools.assert_almost_equal(
            class_to_bps(bps_to_class(bps)) / 1024, expected)

    def test_bps_class_bps(self):
        for bps, expected in (
            (0, 0), (1, 16), (2, 16), (15, 16), (16, 16),
            (17, 17), (1024, 1024),
        ):
            yield self._check_bps_class_bps, bps * 1024, expected

    def _check_class_bps_class(self, bw_cls):
        ntools.assert_almost_equal(
            bps_to_class(class_to_bps(bw_cls)), bw_cls)

    def test_class_bps_class(self):
        for bw_cls in (0, 1, 2, 254, 255):
            yield self._check_class_bps_class, bw_cls


if __name__ == "__main__":
    nose.run(defaultTest=__name__)
