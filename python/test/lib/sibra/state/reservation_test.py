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
:mod:`reservation_test` --- lib.sibra.state.reservation unit tests
==================================================================
"""
# Stdlib
from unittest.mock import patch

# External packages
import nose
import nose.tools as ntools

# SCION
from lib.sibra.state.reservation import ReservationBase, SteadyReservation
from lib.sibra.util import BWSnapshot
from test.testcommon import create_mock


class ReservationBaseTesting(ReservationBase):
    MAX_TICKS = 4
    RESV_TYPE = "resv type"


class TestReservationBaseAdd(object):
    """
    Unit tests for lib.sibra.state.reservation.ReservationBase.add
    """
    @patch("lib.sibra.state.reservation.BWSnapshot", autospec=True)
    @patch("lib.sibra.state.reservation.logging", autospec=True)
    @patch("lib.sibra.state.reservation.BandwidthBase.__init__", autospec=True,
           return_value=None)
    def test_in_use(self, super_init, logging, bwsnap):
        inst = ReservationBaseTesting("path id", "owner", "parent")
        inst.idxes = [0, 2, 7]
        # Call
        ntools.eq_(inst.add(2, "bwsnap", 43, 42), bwsnap.return_value)

    @patch("lib.sibra.state.reservation.BandwidthBase.__init__", autospec=True,
           return_value=None)
    def test_too_large(self, super_init):
        inst = ReservationBaseTesting("path id", "owner", "parent")
        bw_avail = create_mock(["__add__", "min"])
        bw_avail.__add__.return_value = bw_avail
        inst.parent = create_mock(["bw_avail"])
        inst.parent.bw_avail.return_value = bw_avail
        inst.resvs = [8]
        bwsnap = create_mock(["slte"])
        bwsnap.slte.return_value = False
        # Call
        ntools.eq_(inst.add(2, bwsnap, 43, 42), bw_avail.min.return_value)
        # Tests
        bw_avail.__add__.assert_called_once_with(8)
        bwsnap.slte.assert_called_once_with(bw_avail)
        bw_avail.min.assert_called_once_with(bwsnap)

    @patch("lib.sibra.state.reservation.ReservationIndex", autospec=True)
    @patch("lib.sibra.state.reservation.BandwidthBase.__init__", autospec=True,
           return_value=None)
    def test_success(self, super_init, resv_idx):
        inst = ReservationBaseTesting("path id", "owner", "parent")
        inst.parent = create_mock(["bw_avail"])
        inst.parent.bw_avail.return_value = 8
        inst.resvs = [8]
        inst._update = create_mock()
        bwsnap = create_mock(["slte"])
        # Call
        ntools.eq_(inst.add(2, bwsnap, 43, 42), bwsnap)
        # Tests
        resv_idx.assert_called_once_with(2, bwsnap, 43)
        ntools.eq_(inst.idxes, {2: resv_idx.return_value})
        ntools.eq_(inst.order, [2])
        inst._update.assert_called_once_with(42)


class TestReservationBaseUpdate(object):
    """
    Unit tests for lib.sibra.state.reservation.ReservationBase._update

    Note: these tests do not mock out BWSnapshot, as it would make testing too
    complex to be useful.
    """
    @patch("lib.sibra.state.reservation.BandwidthBase.__init__", autospec=True,
           return_value=None)
    def _check(self, old_resvs, resvs, updates, super_init):
        inst = ReservationBaseTesting("path id", "owner", "parent")
        inst.parent = create_mock(["update"])
        inst.resvs = []
        for bw in old_resvs:
            inst.resvs.append(BWSnapshot(bw * 1024, bw * 1024))
        for idx, exp_tick, bw in resvs:
            inst.order.append(idx)
            resv = create_mock(["bwsnap", "exp_tick"])
            resv.bwsnap = BWSnapshot(bw * 1024, bw * 1024)
            resv.exp_tick = exp_tick
            inst.idxes[idx] = resv
        # Call
        inst._update(0)
        # Tests
        if not updates:
            ntools.eq_(inst.parent.update.called, False)
            return
        parent_updates = []
        for idx, bw in updates:
            parent_updates.append((idx, BWSnapshot(bw * 1024, bw * 1024)))
        inst.parent.update.assert_called_once_with(parent_updates)

    def test_no_change(self):
        # 0: 40, 40, 40, 0...
        # 7: 20, 20, 20, 20, 0...
        # 4: 50, 50, 0...
        resvs = [(0, 2, 40), (7, 3, 20), (4, 1, 50)]
        old_resvs = [50, 0, -10, -20, -20]
        self._check(old_resvs, resvs, [])

    def test_update(self):
        # 0: 30, 30, 30, 0...
        # 7: 10, 10, 10, 10, 10, 10, 0...
        # 4: 40, 0...
        resvs = [(0, 2, 30), (7, 5, 10), (4, 0, 40)]
        old_resvs = [50, 0, -10, -20, 0, 0, -20]
        update = [(0, -10), (1, -10), (2, +10), (6, 10)]
        self._check(old_resvs, resvs, update)


class TestReservationBaseNext(object):
    """
    Unit tests for lib.sibra.state.reservation.ReservationBase.next
    """
    @patch("lib.sibra.state.reservation.BWSnapshot", autospec=True)
    @patch("lib.sibra.state.reservation.BandwidthBase.next", autospec=True)
    @patch("lib.sibra.state.reservation.BandwidthBase.__init__", autospec=True,
           return_value=None)
    def test(self, super_init, super_next, bwsnap):
        inst = ReservationBaseTesting("path id", "owner", "parent")
        inst._rollover = create_mock()
        inst._expire = create_mock()
        inst.resvs = ["new max bw"]
        for i in range(3):
            resv = create_mock(["exp_tick"])
            resv.exp_tick = 9 + i
            inst.idxes[i] = resv
        # Call
        inst.next(10)
        # Tests
        super_next.assert_called_once_with(inst)
        inst._rollover.assert_called_once_with(inst.child_resvs)
        ntools.eq_(inst.max_bw, "new max bw")
        ntools.eq_(inst.child_used, bwsnap.return_value)
        inst._expire.assert_called_once_with([0], 10)


class TestReservationBaseUse(object):
    """
    Unit tests for lib.sibra.state.reservation.ReservationBase.use
    """
    @patch("lib.sibra.state.reservation.BandwidthBase.__init__", autospec=True,
           return_value=None)
    def test(self, super_init):
        inst = ReservationBaseTesting("path id", "owner", "parent")
        inst.curr_used = 0
        inst._expire = create_mock()
        inst.order = [6, 7, 9, 0, 2, 4]
        # Call
        ntools.ok_(inst.use(0, 42, 11))
        # Tests
        ntools.eq_(inst.curr_used, 42)
        inst._expire.assert_called_once_with([6, 7, 9], 11)


class TestSteadyReservationUpdate(object):
    """
    Unit tests for lib.sibra.state.reservation.SteadyReservation.update

    Note: these tests do not mock out BWSnapshot, as it would make testing too
    complex to be useful.
    """
    def test(self):
        inst = SteadyReservation("owner", BWSnapshot(100, 100), "parent")
        inst.max_bw = BWSnapshot(100, 100)
        for i, bw in enumerate([50, 0, -10, -20, 0, 0, -20]):
            inst.child_resvs[i] = BWSnapshot(bw, bw)
        updates = []
        for idx, bw in [(0, -10), (1, -10), (2, +10), (6, 10)]:
            updates.append((idx, BWSnapshot(bw, bw)))
        # Call
        inst.update(updates)
        # Tests
        for i, bw in enumerate([40, -10, 0, -20, 0, 0, -10]):
            tick = BWSnapshot(bw, bw)
            ntools.eq_(inst.child_resvs[i], tick)

if __name__ == "__main__":
    nose.run(defaultTest=__name__)
