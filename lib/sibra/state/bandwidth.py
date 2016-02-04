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
    def __init__(self, owner):
        self.owner = owner
        self.curr_used = BWSnapshot()
        # Using MAX_TICKS+1 allow for bandwidth reduction after a
        # max-length reservation
        self.ticks = [BWSnapshot() for i in range(self.MAX_TICKS+1)]

    def next(self):
        old_resv = self.ticks.pop(0)
        self.ticks[0] += old_resv
        self.ticks.append(BWSnapshot())
        self.curr_used = BWSnapshot()


class LinkBandwidth(BandwidthBase):
    """
    Track bandwidth usage and reservations on a link.

    For link bandwidth the 'forward' direction is sending traffic over the link,
    and 'reverse' is receiving traffic from the link.
    """
    MAX_TICKS = max(SIBRA_MAX_STEADY_TICKS, SIBRA_MAX_EPHEMERAL_TICKS)

    def __init__(self, owner, max_bw):
        super().__init__(owner)
        self.max_bw = max_bw

    def update(self, updates):
        """
        Apply a list of bandwidth updates to the reservation predictions. The
        updates are in the form [(tick, val)] where the former specifies which
        tick the change happens in, and val is a relative bandwidth change.
        """
        total_resv = BWSnapshot()
        for exp_tick_rel, val in updates:
            self.ticks[exp_tick_rel] += val
            total_resv += self.ticks[exp_tick_rel]
            assert total_resv.slte(self.max_bw)

    def bw_avail(self):
        """
        Return the max available bandwidth. As all reservations cannot start in
        the future, the current snapshot is also the maximum bandwidth used.
        """
        return self.max_bw - self.ticks[0]

    def __str__(self):
        return ("Link: Owner: %s Used/Max bandwidth (Kibit/s): "
                "Fwd: %.1f/%.1f Rev: %.1f/%.1f" % (
                    self.owner, self.ticks[0].fwd/1024, self.max_bw.fwd/1024,
                    self.ticks[0].rev/1024, self.max_bw.rev/1024))
