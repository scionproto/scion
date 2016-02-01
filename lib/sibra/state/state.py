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
:mod:`state` --- SIBRA state
============================
"""
# Stdlib
import logging

# SCION
from lib.defines import (
    SIBRA_MAX_STEADY_TICKS,
)
from lib.packet.scion_addr import ISD_AD
from lib.sibra.util import (
    BWSnapshot,
    current_tick,
)
from lib.sibra.state.bandwidth import LinkBandwidth
from lib.sibra.state.reservation import SteadyReservation


RESV_INDEXES = 16


class SibraState(object):
    """
    Track bandwidth usage and all reservations that traverse a link.
    """
    def __init__(self, bw, isd_id):
        self.curr_tick = current_tick()
        self.link = LinkBandwidth(isd_id, BWSnapshot(bw * 1024, bw * 1024))
        self.steady = {}
        self.pend_steady = {}
        self.ephemeral = {}
        self.pend_ephemeral = {}
        self.pending = {}
        logging.info("Initialized SibraState: %s", self.link)

    def _update_tick(self):
        """
        Perform the tick update steps until the state is updated to the current
        tick.
        """
        now = current_tick()
        while self.curr_tick < now:
            self.curr_tick += 1
            self.link.next()
            self._resv_tick(self.steady)
            self._resv_tick(self.ephemeral)

    def _resv_tick(self, resv_dict):
        """
        Update all reservations to the next tick, removing any that no longer
        have active indexes.
        """
        remove = []
        for path_id, resv in resv_dict.items():
            if not resv.next(self.curr_tick):
                remove.append(path_id)
        for path_id in remove:
            del resv_dict[path_id]

    def steady_add(self, path_id, resv_idx, bwsnap, exp_tick, accepted,
                   setup=True):
        """
        Add a new steady path, or renew an existing one, returning a bandwidth
        suggestion if the request is not allowed.
        """
        self._update_tick()
        if setup:
            # FIXME(kormat): switch to exceptions
            assert path_id not in self.pend_steady
            assert path_id not in self.steady
            owner = ISD_AD.from_raw(path_id[:ISD_AD.LEN])
            resv = SteadyReservation(path_id, owner, self.link)
        else:
            resv = self.steady.get(path_id)
        if not resv:
            return BWSnapshot()
        assert exp_tick >= self.curr_tick
        assert (exp_tick - self.curr_tick) <= SIBRA_MAX_STEADY_TICKS
        bwhint = resv.add(resv_idx, bwsnap, exp_tick, self.curr_tick)
        if not accepted or bwhint != bwsnap:
            if bwhint != bwsnap:
                logging.debug("Requested: %s Available bandwidth: %s", bwsnap,
                              bwhint)
            return bwhint.to_classes(floor=True).floor()
        if setup:
            # The setup request has been accepted, so add the reservation to the
            # list of steady paths, and flag it as pending.
            self.steady[path_id] = resv
            self.pend_steady[path_id] = True

    def steady_use(self, path_id, resv_idx, bw_used):
        """
        Update state when a packet uses a steady path.
        """
        self._update_tick()
        resv = self.steady.get(path_id)
        # FIXME(kormat): switch to exception
        if not resv:
            return False
        return resv.use(resv_idx, bw_used, self.curr_tick)

    def steady_idx_remove(self, path_id, resv_idx):
        """
        Remove a reservation index.
        """
        self._update_tick()
        resv = self.steady.get(path_id)
        # FIXME(kormat): switch to exception
        assert resv
        resv.remove(resv_idx, self.curr_tick)

    def steady_pend_confirm(self, path_id):
        """
        Confirm a pending steady path, meaning that it has been used.
        """
        self._update_tick()
        self.pend_steady.pop(path_id, None)

    def steady_pend_remove(self, path_id):
        """
        Remove a pending steady path, as it has either been denied by a later
        hop, or timed out.
        """
        self._update_tick()
        if self.pend_steady.pop(path_id, None):
            self.steady[path_id].remove_all()

    def steady_remove(self, path_id):
        """
        Remove an active steady path.
        """
        self._update_tick()
        resv = self.steady.get(path_id)
        # FIXME(kormat): switch to exception
        if not resv:
            return False
        return resv.remove_all()

    def __str__(self):
        tmp = ["SibraState:"]
        tmp.append("  %s" % self.link)
        tmp.extend(self._format_resv("Steady reservations", self.steady,
                                     self.pend_steady))
        tmp.extend(self._format_resv("Ephemeral reservations", self.ephemeral,
                                     self.pend_ephemeral))
        return "\n".join(tmp)

    def _format_resv(self, name, resv_dict, pend_dict):
        """
        Format the current and pending reservations for printing
        """
        tmp = []
        if not resv_dict:
            return []
        tmp.append("  %s:" % name)
        active = []
        pending = []
        for pathid in sorted(resv_dict):
            if pathid in pend_dict:
                pending.append(pathid)
            else:
                active.append(pathid)
        if active:
            tmp.append("    Active(%d):" % len(active))
        for pathid in active:
            for line in str(resv_dict[pathid]).splitlines():
                tmp.append("      %s" % line)
        if pending:
            tmp.append("    Pending(%d):" % len(pending))
        for pathid in pending:
            for line in str(resv_dict[pathid]).splitlines():
                tmp.append("      %s" % line)
        return tmp
