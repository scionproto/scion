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
from lib.packet.scion_addr import ISD_AS
from lib.sibra.util import BWSnapshot, current_tick
from lib.sibra.state.bandwidth import LinkBandwidth
from lib.sibra.state.reservation import EphemeralReservation, SteadyReservation


RESV_INDEXES = 16


class SibraState(object):
    """
    Track bandwidth usage and all reservations that traverse a link.
    """
    def __init__(self, bw, link_name):  # pragma: no cover
        self.curr_tick = current_tick()
        self.link = LinkBandwidth(link_name, BWSnapshot(bw * 1024, bw * 1024))
        self.steady = {}
        self.pend_steady = {}
        self.ephemeral = {}
        self.pend_ephemeral = {}
        self.pending = {}
        logging.info("Initialized SibraState: %s", self.link)

    def update_tick(self):
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

    def add_steady(self, path_id, resv_idx, bwsnap, exp_tick, accepted,
                   setup=True):
        """
        Add a new steady path, or renew an existing one, returning a bandwidth
        suggestion if the request is not allowed.
        """
        self.update_tick()
        if setup:
            resv = self._create_steady(path_id)
        else:
            resv = self.steady[path_id]
        bwcls = self._add(resv, resv_idx, bwsnap, exp_tick, accepted)
        if bwcls:  # Request was not allowed, so return the hint
            return bwcls
        if setup:
            # The setup request has been accepted, so add the reservation to the
            # list of steady paths, and flag it as pending.
            self.steady[path_id] = resv
            self.pend_steady[path_id] = True

    def add_ephemeral(self, path_id, steady_id, resv_idx, bwsnap, exp_tick,
                      accepted, setup=True):
        """
        Add a new ephemeral path, or renew an existing one, returning a
        bandwidth suggestion if the request is not allowed.
        """
        self.update_tick()
        if setup:
            resv = self._create_ephemeral(path_id, steady_id)
        else:
            resv = self.ephemeral[path_id]
        bwcls = self._add(resv, resv_idx, bwsnap, exp_tick, accepted)
        if bwcls:  # Request was not allowed, so return the hint
            return bwcls
        if setup:
            # The setup request has been accepted, so add the reservation to the
            # list of ephemeral paths, and flag it as pending.
            self.steady[steady_id].add_child(path_id)
            self.ephemeral[path_id] = resv
            self.pend_ephemeral[path_id] = True

    def _add(self, resv, resv_idx, bwsnap, exp_tick, accepted):
        bwhint = resv.add(resv_idx, bwsnap, exp_tick, self.curr_tick)
        if not accepted or bwhint != bwsnap:
            # Accepted will be false when an earlier hop has already rejected
            # the request.
            if bwhint != bwsnap:
                logging.debug("Requested: %s Available bandwidth: %s", bwsnap,
                              bwhint)
            return bwhint.to_classes(floor=True).floor()

    def _create_steady(self, path_id):  # pragma: no cover
        # FIXME(kormat): switch to exceptions
        assert path_id not in self.pend_steady
        assert path_id not in self.steady
        owner = ISD_AS(path_id[:ISD_AS.LEN])
        return SteadyReservation(path_id, owner, self.link)

    def _create_ephemeral(self, path_id, steady_id):  # pragma: no cover
        # FIXME(kormat): switch to exceptions
        assert path_id not in self.pend_ephemeral
        assert path_id not in self.ephemeral
        assert steady_id in self.steady
        owner = ISD_AS(path_id[:ISD_AS.LEN])
        return EphemeralReservation(path_id, owner, self.steady[steady_id])

    def _get_resv(self, path_id, steady):  # pragma: no cover
        if steady:
            return self.steady.get(path_id)
        return self.ephemeral.get(path_id)

    def use(self, path_id, resv_idx, bw_used, steady):  # pragma: no cover
        """
        Update state when a packet uses a reservation
        """
        self.update_tick()
        resv = self._get_resv(path_id, steady)
        if not resv:
            return False
        return resv.use(resv_idx, bw_used, self.curr_tick)

    def idx_remove(self, path_id, resv_idx, steady):  # pragma: no cover
        """
        Remove a reservation index.
        """
        self.update_tick()
        resv = self._get_resv(path_id, steady)
        # FIXME(kormat): switch to exception
        assert resv
        resv.remove(resv_idx, self.curr_tick)

    def pend_confirm(self, path_id, steady):  # pragma: no cover
        """
        Confirm a pending path, meaning that it has been used.
        """
        self.update_tick()
        if steady:
            self.pend_steady.pop(path_id, None)
        else:
            self.pend_ephemeral.pop(path_id, None)

    def pend_remove(self, path_id, steady):  # pragma: no cover
        """
        Remove a pending path, as it has either been denied by a later
        hop, or timed out.
        """
        self.update_tick()
        pend = self.pend_steady
        paths = self.steady
        if not steady:
            pend = self.pend_ephemeral
            paths = self.ephemeral
        if pend.pop(path_id, None):
            paths[path_id].remove_all(self.curr_tick)
            del paths[path_id]

    def remove(self, path_id, steady):  # pragma: no cover
        """Remove an active path."""
        self.update_tick()
        resv = self._get_resv(path_id, steady)
        if not resv:
            return False
        return resv.remove_all(self.curr_tick)

    def __str__(self):
        tmp = ["SibraState:"]
        tmp.append("  %s" % self.link)
        tmp.extend(self._format_resv("Steady reservations", self.steady,
                                     self.pend_steady))
        tmp.extend(self._format_resv("Ephemeral reservations", self.ephemeral,
                                     self.pend_ephemeral))
        return "\n".join(tmp)

    def _format_resv(self, name, resv_dict, pend_dict):  # pragma: no cover
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
