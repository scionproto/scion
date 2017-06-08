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
:mod:`bandwidth` --- SIBRA bandwidth classes
============================================
"""
# SCION
from lib.defines import (
    SIBRA_MAX_EPHEMERAL_TICKS,
    SIBRA_MAX_STEADY_TICKS,
)
from lib.sibra.util import BWSnapshot


RESV_INDEXES = 16


class BandwidthBase(object):
    """
    Base class for tracking bandwidth usage and predictions.
    """
    def __init__(self, owner, max_bw=None):  # pragma: no cover
        self.owner = owner
        self.curr_used = BWSnapshot()
        self.max_bw = max_bw or BWSnapshot()
        # The first entry is the current absolute bandwidth reserved. All
        # subsequent entries are relative updates. This means that a value of 0
        # indicates the bandwidth doesn't change for that tick.
        # Using MAX_TICKS+1 allows for bandwidth reduction after a max-length
        # reservation
        self.resvs = [BWSnapshot() for i in range(self.MAX_TICKS+1)]

    def next(self):  # pragma: no cover
        self._rollover(self.resvs)
        self.curr_used = BWSnapshot()

    def _rollover(self, items):  # pragma: no cover
        old = items.pop(0)
        items[0] += old
        items.append(BWSnapshot())


class LinkBandwidth(BandwidthBase):
    """
    Track bandwidth usage and reservations on a link.

    For link bandwidth the 'forward' direction is sending traffic over the link,
    and 'reverse' is receiving traffic from the link.
    """
    MAX_TICKS = max(SIBRA_MAX_STEADY_TICKS, SIBRA_MAX_EPHEMERAL_TICKS)

    def update(self, updates):
        """
        Apply a list of bandwidth updates to the reservation predictions. The
        updates are in the form [(tick, val)] where the former specifies which
        tick the change happens in, and val is a relative bandwidth change.
        """
        for exp_tick_rel, val in updates:
            self.resvs[exp_tick_rel] += val
        assert self.resvs[0].slte(self.max_bw)

    def bw_avail(self):  # pragma: no cover
        """
        Return the max available bandwidth. As all reservations cannot start in
        the future, the current snapshot is also the maximum bandwidth used.
        """
        return self.max_bw - self.resvs[0]

    def short_desc(self):  # pragma: no cover
        return "Link: %s" % self.owner

    def __str__(self):
        return ("Link: %s Used/Max bandwidth (Kibit/s): "
                "Fwd: %.1f/%.1f Rev: %.1f/%.1f" % (
                    self.owner, self.resvs[0].fwd/1024, self.max_bw.fwd/1024,
                    self.resvs[0].rev/1024, self.max_bw.rev/1024))
