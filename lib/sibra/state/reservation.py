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
    def __init__(self, pathid, owner, link):
        super().__init__(owner)
        self.pathid = pathid
        self.link = link
        self.idxes = {}
        self.order = []

    def add(self, idx, bwsnap, exp_tick, curr_tick):
        """
        Add a new reservation index. If the index is already in use, the request
        is rejected by returning a zero-bandwidth snapshot. If the request is
        too large, a suggested bandwidth is returned instead.
        """
        if idx in self.idxes or idx in self.order:
            return BWSnapshot()
        bw_avail = self.link.bw_avail() + self.ticks[0]
        if not bwsnap.slte(bw_avail):
            return bw_avail.min(bwsnap)
        self.idxes[idx] = ReservationIndex(idx, bwsnap, exp_tick)
        self.order.append(idx)
        self._update(curr_tick)
        return bwsnap

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

    def _update(self, curr_tick):
        """
        Update the predicted bandwidth reservations, and pass the differences to
        the link.
        """
        updates = []
        last_bw = BWSnapshot()
        for i, old_tick in enumerate(self.ticks):
            exp_tick = curr_tick + i
            bwsnap = BWSnapshot()
            active = False
            for idx in self.order:
                resv_idx = self.idxes[idx]
                if resv_idx.exp_tick >= exp_tick:
                    active = True
                    bwsnap.max(resv_idx.bwsnap)
            diff_bw = bwsnap - last_bw
            if diff_bw != old_tick:
                updates.append((i, diff_bw - old_tick))
                self.ticks[i] = diff_bw
            last_bw = bwsnap
            if not active:
                # Nothing more to look at
                break
        if updates:
            self.link.update(updates)

    def next(self, curr_tick):
        """
        Roll over to the next SIBRA tick, removing any indexes which have
        expired.
        """
        super().next()
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

    def __str__(self):
        tmp = []
        tmp.append("%s path ID: %s Owner: %s" % (
            self.RESV_TYPE, hex_str(self.pathid), self.owner))
        for i in self.order:
            for line in str(self.idxes[i]).splitlines():
                tmp.append("  %s" % line)
        return "\n".join(tmp)


class SteadyReservation(ReservationBase):
    RESV_TYPE = "Steady"
    MAX_TICKS = SIBRA_MAX_STEADY_TICKS


class EphemeralReservation(ReservationBase):
    RESV_TYPE = "Ephemeral"
    MAX_TICKS = SIBRA_MAX_EPHEMERAL_TICKS


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
