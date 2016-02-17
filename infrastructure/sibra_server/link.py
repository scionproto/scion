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
:mod:`link` --- link management
===============================
"""
# Stdlib
import logging
import threading

# SCION
from infrastructure.sibra_server.steady import (
    SteadyPath,
    SteadyPathErrorNoReservation,
)
from infrastructure.sibra_server.util import seg_to_hops
from lib.sibra.state.state import SibraState
from lib.sibra.util import BWSnapshot


class Link(object):
    """
    The Link class handles steady path management on a single interface.
    """
    def __init__(self, addr, sendq, signing_key, iface):
        """
        :param ScionAddr addr: the address of this sibra server
        :param queue.Queue sendq:
            packets written to this queue will be sent by the sibra server
            thread.
        :param bytes signing_key: AS signing key.
        :param topology.InterfaceElement iface: the interface to manage.
        """
        self.addr = addr
        self.sendq = sendq
        self.iface = iface
        self.signing_key = signing_key
        self.neigh = iface.isd_as
        self.id = iface.if_id
        self.state = SibraState(iface.bandwidth, self.addr.isd_as)
        self.segments = {}
        self.parent = iface.link_type == "PARENT"
        self.steadies = {}
        self.lock = threading.Lock()

    def update_segment(self, pcb):
        """
        Add to or update the list of segments that use this interface
        """
        last = pcb.get_last_pcbm()
        assert last.hof.ingress_if == self.id
        hops = seg_to_hops(pcb)
        with self.lock:
            if hops in self.segments:
                new_exp = pcb.get_expiration_time()
                old_exp = self.segments[hops].get_expiration_time()
                if new_exp <= old_exp:
                    return
                logging.debug("Updating segment for interface %s: %s",
                              self.id, pcb.short_desc())
            else:
                logging.info("Adding segment for interface %s: %s",
                             self.id, pcb.short_desc())
            self.segments[hops] = pcb

    def steady_add(self):
        """
        Set up a new steady path using this interface
        """
        if not self.segments:
            logging.warning(
                "Link.setup: no segments for this interface. %s", self)
            return
        # FIXME(kormat): un-hardcode these bandwidths
        bwsnap = BWSnapshot(25 * 1024, 15 * 1024)
        with self.lock:
            steady = SteadyPath(self.addr, self.sendq, self.signing_key,
                                self._pick_seg(), bwsnap)
            self.steadies[steady.id] = steady
            steady.setup()

    def _pick_seg(self):
        """
        Select the segment to use for a steady path
        """
        # FIXME(kormat): this needs actual logic
        segs = list(self.segments.values())
        return segs[0]

    def steady_renew(self):
        """
        Renew all existing steady paths
        """
        remove = []
        with self.lock:
            for steady in self.steadies.values():
                try:
                    steady.renew()
                except SteadyPathErrorNoReservation:
                    remove.append(steady.id)
            for path_id in remove:
                logging.info("Removing expired reservation: %s",
                             self.steadies[path_id])
                del self.steadies[path_id]

    def process(self, pkt, ext):
        """
        Process an incoming steady path packet
        """
        assert ext.steady
        logging.debug(pkt)
        if ext.req_block:
            with self.lock:
                if ext.fwd:
                    self._process_req(pkt, ext)
                else:
                    self._process_reply(pkt, ext)
        else:
            logging.error("Received a non-request sibra packet:\n%s", pkt)

    def _process_req(self, pkt, ext):
        """
        Process a steady path request
        """
        assert ext.path_ids[0] not in self.steadies
        if not ext.accepted:
            # Request was already rejected, so just send the packet back.
            pkt.reverse()
            self.sendq.put(pkt)
            return
        req_info = ext.req_block.info
        bwsnap = req_info.bw.to_snap()
        bwhint = self.state.steady_add(ext.path_ids[0], req_info.index, bwsnap,
                                       req_info.exp_tick, True, ext.setup)
        if bwhint is not None:
            # This shouldn't happen - if the local ER accepted the reservation,
            # then there should be enough bandwidth available for it. This means
            # our state is out of sync.
            logging.critical("Requested: %s Available bandwidth: %s",
                             bwsnap, bwhint)
            return
        # All is good, return the packet to the requestor.
        pkt.reverse()
        self.sendq.put(pkt)

    def _process_reply(self, pkt, ext):
        """
        Process a reply to a steady path request
        """
        assert ext.path_ids[0] in self.steadies
        steady = self.steadies[ext.path_ids[0]]
        steady.process_reply(pkt, ext)

    def __str__(self):
        return "<Link: %s to %s>" % (self.id, self.neigh)
