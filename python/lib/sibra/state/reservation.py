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
:mod:`reservation` --- SIBRA reservation classes
================================================
"""
# Stdlib
import logging

# SCION
from lib.defines import (
    SIBRA_MAX_EPHEMERAL_TICKS,
    SIBRA_MAX_STEADY_TICKS,
)
from lib.sibra.state.bandwidth import BandwidthBase
from lib.sibra.util import BWSnapshot, tick_to_time
from lib.util import hex_str, iso_timestamp


class ReservationBase(BandwidthBase):
    """
    Base class for managing bandwidth reservations.

    A given reservation can have up to SIBRA_MAX_IDX reservations at a point in
    time, and will generally be cycling through indexes as old ones expire and
    new ones are requested. This class keeps the indexes sorted in chronological
    order, and using a newer index automatically expires older indexes.
    """
    def __init__(self, pathid, owner, parent):
        super().__init__(owner)
        self.pathid = pathid
        self.parent = parent
        self.children = []
        self.child_resvs = [BWSnapshot() for i in range(self.MAX_TICKS+1)]
        self.child_used = BWSnapshot()
        self.idxes = {}
        self.order = []

    def add(self, idx, bwsnap, exp_tick, curr_tick):
        """
        Add a new reservation index. If the index is already in use, the request
        is rejected by returning a zero-bandwidth snapshot. If the request is
        too large, a suggested bandwidth is returned instead.
        """
        assert exp_tick >= curr_tick
        assert (exp_tick - curr_tick) <= self.MAX_TICKS
        if idx in self.idxes or idx in self.order:
            logging.error("Idx %s already in use:\n%s", idx, self)
            return BWSnapshot()
        bw_avail = self.parent.bw_avail() + self.resvs[0]
        if not bwsnap.slte(bw_avail):
            return bw_avail.min(bwsnap)
        self.idxes[idx] = ReservationIndex(idx, bwsnap, exp_tick)
        self.order.append(idx)
        self._update(curr_tick)
        return bwsnap

    def add_child(self, child_id):  # pragma: no cover
        assert child_id not in self.children
        self.children.append(child_id)

    def remove_child(self, child_id):  # pragma: no cover
        self.children.remove(child_id)

    def remove(self, idx, curr_tick):  # pragma: no cover
        """
        Remove a reservation index.
        """
        # FIXME(kormat): switch to exception
        assert idx in self.idxes
        assert idx in self.order
        del self.idxes[idx]
        self.order.remove(idx)
        self._update(curr_tick)

    def remove_all(self, curr_tick):  # pragma: no cover
        """
        Remove all reservation indexes.
        """
        # Used when a request is rejected
        self.idxes = {}
        self.order = []
        self._update(curr_tick)
        if self.RESV_TYPE == "Ephemeral":
            self.parent.remove_child(self.pathid)

    def _update(self, curr_tick):
        """
        Update the predicted bandwidth reservations, and pass the differences to
        the parent.
        """
        updates = []
        last_bw = BWSnapshot()
        for i, old_resv in enumerate(self.resvs):
            exp_tick = curr_tick + i
            bwsnap = BWSnapshot()
            active = False
            for idx in self.order:
                resv_idx = self.idxes[idx]
                if resv_idx.exp_tick >= exp_tick:
                    active = True
                    bwsnap.max(resv_idx.bwsnap)
            diff_bw = bwsnap - last_bw
            if diff_bw != old_resv:
                updates.append((i, diff_bw - old_resv))
                self.resvs[i] = diff_bw
            last_bw = bwsnap
            if not active:
                # Nothing more to look at
                break
        if updates:
            self.parent.update(updates)

    def next(self, curr_tick):
        """
        Roll over to the next SIBRA tick, removing any indexes which have
        expired.
        """
        super().next()
        self._rollover(self.child_resvs)
        self.max_bw = self.resvs[0]
        self.child_used = BWSnapshot()
        expired = []
        for idx, resv in self.idxes.items():
            if resv.exp_tick < curr_tick:
                expired.append(idx)
        if expired:
            self._expire(expired, curr_tick)
        return len(self.idxes)

    def _expire(self, idxes, curr_tick):  # pragma: no cover
        for idx in idxes:
            del self.idxes[idx]
            self.order.remove(idx)
        self._update(curr_tick)

    def use(self, resv_idx, bw_used, curr_tick):
        """
        Use the specified index, automatically expiring any older indexes.
        """
        expired = []
        found = False
        for idx in self.order:
            if resv_idx == idx:
                found = True
                break
            expired.append(idx)
        if found:
            self.curr_used += bw_used
        if expired:
            self._expire(expired, curr_tick)
        return found

    def short_desc(self):  # pragma: no cover
        return "%s path ID: %s Owner: %s" % (
            self.RESV_TYPE, hex_str(self.pathid), self.owner)

    def __str__(self):
        tmp = []
        tmp.append("%s Parent: (%s)" %
                   (self.short_desc(), self.parent.short_desc()))
        for i in self.order:
            for line in str(self.idxes[i]).splitlines():
                tmp.append("  %s" % line)
        if self.children:
            tmp.append(
                "Children: %d. Used/Reserved bandwidth (Kibit/s): "
                "%.1f/%.1f Rev: %.1f/%.1f" % (
                    len(self.children), self.child_used.fwd/1024,
                    self.child_resvs[0].fwd/1024, self.child_used.rev/1024,
                    self.child_resvs[0].rev/1024,
                ))
        return "\n".join(tmp)


class SteadyReservation(ReservationBase):
    RESV_TYPE = "Steady"
    MAX_TICKS = SIBRA_MAX_STEADY_TICKS

    def update(self, updates):
        """
        Apply a list of bandwidth updates to the reservation predictions. The
        updates are in the form [(tick, val)] where the former specifies which
        tick the change happens in, and val is a relative bandwidth change.
        """
        for exp_tick_rel, val in updates:
            self.child_resvs[exp_tick_rel] += val
        assert self.child_resvs[0].slte(self.max_bw)

    def bw_avail(self):  # pragma: no cover
        return self.max_bw - self.child_resvs[0]


class EphemeralReservation(ReservationBase):
    RESV_TYPE = "Ephemeral"
    MAX_TICKS = SIBRA_MAX_EPHEMERAL_TICKS

    def next(self, curr_tick):  # pragma: no cover
        count = super().next(curr_tick)
        if not count:
            self.parent.remove_child(self.pathid)
        return count


class ReservationIndex(object):
    def __init__(self, idx, bwsnap, exp_tick):  # pragma: no cover
        self.idx = idx
        self.bwsnap = bwsnap
        self.exp_tick = exp_tick

    def __str__(self):
        return "Idx: %2s Fwd:%s Rev:%s Expiry: %s" % (
            self.idx, self.bwsnap.fwd_str(), self.bwsnap.rev_str(),
            iso_timestamp(tick_to_time(self.exp_tick)),
        )
