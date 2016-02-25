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
:mod:`steady` --- SIBRA Steady path extension
=============================================
"""
# Stdlib
import logging
import os
import struct

# SCION
from lib.defines import SIBRA_STEADY_ID_LEN
from lib.sibra.ext.ext import SibraExtBase
from lib.sibra.ext.info import ResvInfoSteady
from lib.sibra.ext.offer import OfferBlockSteady
from lib.sibra.ext.resv import ResvBlockSteady
from lib.sibra.util import BWSnapshot
from lib.types import RouterFlag


class SibraExtSteady(SibraExtBase):
    """
    SIBRA Steady path extension header.

    Steady paths are long-lived reservations setup by ASes, to provide
    guarantees about bandwidth availability to their customers. The setup packet
    travels along a normal SCION path, and only after it's successful do the
    packets switch to using the (newly-created) SIBRA path. Steady paths only
    have a single path ID.
    """
    NAME = "SibraExtSteady"
    STEADY = True

    def _parse(self, raw):
        data, req = self._parse_start(raw)
        self.path_ids.append(self._parse_path_id(data))
        if not self.setup:
            self.active_blocks.append(
                self._parse_block(data, self.path_lens[0], self.STEADY))
        self._parse_end(data, req)

    @classmethod
    def from_values(cls, *args, **kwargs):
        raise NotImplementedError

    @classmethod
    def setup_from_values(cls, req_info, total_hops, path_id, setup=True):
        """
        Construct a setup request header.
        """
        inst = cls()
        inst.setup = setup
        inst.total_hops = total_hops
        inst.path_ids = [path_id]
        inst.req_block = ResvBlockSteady.from_values(req_info, inst.total_hops)
        inst._set_size()
        return inst

    @classmethod
    def use_from_values(cls, path_id, block):
        """
        Construct a header to use the supplied reservation block
        """
        inst = cls()
        inst.path_ids = [path_id]
        inst.total_hops = block.num_hops
        inst.switch_resv([block])
        return inst

    @staticmethod
    def mk_path_id(isd_as):  # pragma: no cover
        return isd_as.pack() + os.urandom(SIBRA_STEADY_ID_LEN - isd_as.LEN)

    def pack(self):
        raw = self._pack_start()
        raw.append(struct.pack("!Bxx", self.total_hops))
        return self._pack_end(raw)

    def renew(self, req_info):  # pragma: no cover
        """
        Renew the current reservation with the specified reservation info.
        """
        self.accepted = True
        self.req_block = ResvBlockSteady.from_values(req_info, self.total_hops)
        self._set_size()

    def teardown(self):  # pragma: no cover
        """
        Shut down the current reservation.
        """
        # FIXME(kormat): not implemented yet in sibra state.
        req_info = ResvInfoSteady.from_values(0, BWSnapshot(), 0)
        self.req_block = ResvBlockSteady.from_values(req_info, self.total_hops)
        self._set_size()

    def _process(self, state, spkt, dir_fwd, key):
        """
        Process a SIBRA steady packet in transit.
        """
        if not self.setup and not self._verify_sof(key):
            # The packet is invalid, so tell the router the packet has been
            # handled, and let it be dropped.
            return [(RouterFlag.ERROR, "Invalid packet")]
        flags = []
        if self.setup:
            logging.debug("SIBRA Steady setup")
            flags.extend(self._process_setup(state, spkt, dir_fwd, key))
            return flags
        if self.req_block:
            logging.debug("SIBRA Steady renewal")
            flags.extend(self._process_renewal(state, spkt, dir_fwd, key))
        flags.extend(self._process_use(state, spkt, dir_fwd))
        return flags

    def _process_setup(self, state, spkt, dir_fwd, key):
        """
        Process a packet containing a setup request. If it's on the return trip,
        update the local SIBRA state appropriately.
        """
        if not self.fwd:
            # Request on return trip
            if self.accepted:
                state.steady_pend_confirm(self.path_ids[0])
            else:
                # Reservation has been rejected by further along the path.
                state.steady_pend_remove(self.path_ids[0])
            # Route packet as normal
        else:
            self._process_req(state, spkt, dir_fwd, key)
        return []

    def _process_renewal(self, state, spkt, dir_fwd, key):
        """
        Process a packet containing a reservation renewal. If it's on the return
        trip, update the local SIBRA state appropriately.
        """
        if not self.fwd:
            # Renewal return trip
            req_info = self.req_block.info
            if not self.accepted and req_info.fail_hop > self.curr_hop:
                state.steady_idx_remove(self.path_ids[0], req_info.index)
        else:
            self._process_req(state, spkt, dir_fwd, key, setup=False)
        return []

    def _process_use(self, state, spkt, dir_fwd):
        """
        Process a packet using a steady reservation.
        Update the appropriate usage counters, and determine the next hop.
        """
        bw_used = BWSnapshot(len(spkt) * 8)
        if not dir_fwd:
            bw_used.reverse()
        logging.debug("SIBRA Steady use")
        if not state.steady_use(
                self.path_ids[0], self.active_blocks[0].info.index, bw_used):
            return [(RouterFlag.ERROR, "Steady path packet rejected")]
        return [(RouterFlag.FORWARD, self.get_next_ifid())]

    def _process_req(self, state, spkt, dir_fwd, key, setup=True):
        """
        Process a packet containing a request (setup or renewal) and handle
        success/denial appropriately.
        """
        req_info = self.req_block.info
        bwsnap = req_info.bw.to_snap()
        if not dir_fwd:
            bwsnap.reverse()
        bw_hint = state.steady_add(
            self.path_ids[0], req_info.index, bwsnap, req_info.exp_tick,
            self.accepted, setup)
        if self.accepted and not bw_hint:
            # Hasn't been previously rejected, and no suggested bandwidth from
            # steady_add, so the request is accepted.
            self._req_accepted(spkt, dir_fwd, key)
        else:
            self._req_denied(dir_fwd, bw_hint)

    def _req_accepted(self, spkt, dir_fwd, key):
        """
        Add a SOF to the request block, but only if one of these is true:
        - this is an egress hop
        - this is the ingress hop at the destination
        """
        if dir_fwd or (self.curr_hop == self.total_hops - 1):
            self._add_hop(spkt, key, self.path_ids[:1])

    def _req_denied(self, dir_fwd, bw_hint):
        """
        Handle denying a request. If this is the first rejection, then switch
        the request block to an offer block, otherwise add/update an offer as
        appropriate.
        """
        if not dir_fwd:
            bw_hint.reverse()
        if self.accepted:
            # First hop to reject the request
            self._reject_req(bw_hint)
            return
        if dir_fwd:
            # Req was already rejected, and this is on egress, so update the
            # offer that the ingress ER made.
            assert self.curr_hop >= self.req_block.info.fail_hop
            offer_hop = self.curr_hop - self.req_block.info.fail_hop
            curr_offer = self.req_block.offers[offer_hop]
            curr_offer.min(bw_hint)
        else:
            # Req was already rejected, and this is on ingress, so add a new
            # offer.
            self.req_block.add(self.curr_hop, bw_hint)

    def _reject_req(self, bw_hint):
        """
        Switch from a request block to an offer block.
        """
        logging.warning("SIBRA request failed, changing to offer block")
        req_info = self.req_block.info
        req_info.fail_hop = self.curr_hop
        self.accepted = False
        self.req_block = OfferBlockSteady.from_values(
            req_info, self.total_hops - self.curr_hop + 1)
        self.req_block.add(self.curr_hop, bw_hint)
        self._set_size()

    def _add_hop(self, spkt, key, path_ids):
        """
        Handle adding an SOF to a request block

        Normally the interface information is in the active SOF field, but
        steady setup packets are special as they travel along a SCION path, so
        extract the interfaces from there.
        """
        if not self.setup:
            super()._add_hop(key, path_ids)
            return
        iof = spkt.path.get_iof()
        hof = spkt.path.get_hof()
        if iof.up_flag:
            self.req_block.add_hop(hof.egress_if, hof.ingress_if, key, path_ids)
        else:
            self.req_block.add_hop(hof.ingress_if, hof.egress_if, key, path_ids)

    def _verify_sof(self, key):
        """
        Verify the current SOF field.
        """
        block = self.active_blocks[0]
        curr_sof = block.sofs[self.curr_hop]
        if curr_sof.mac == curr_sof.calc_mac(
                block.info, key, self.path_ids, self._get_prev_raw()):
            return True
        logging.error("MAC verification failed")
        return False

    def _get_prev_raw(self):
        block = self.active_blocks[0]
        if block.info.fwd_dir:
            if self.curr_hop > 0:
                return block.sofs[self.curr_hop - 1].pack()
        elif self.curr_hop < (block.num_hops - 1):
            return block.sofs[self.curr_hop + 1].pack()
        return None

    def get_next_ifid(self):
        if self.setup:
            return None
        sof = self.active_sof()
        info = self.active_blocks[0].info
        if self.fwd == info.fwd_dir:
            return sof.egress
        else:
            return sof.ingress
