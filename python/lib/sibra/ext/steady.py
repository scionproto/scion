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
import os
import struct

# SCION
from lib.defines import SIBRA_STEADY_ID_LEN
from lib.sibra.ext.ext import SibraExtBase
from lib.sibra.ext.info import ResvInfoSteady
from lib.sibra.ext.offer import OfferBlockSteady
from lib.sibra.ext.resv import ResvBlockSteady
from lib.sibra.util import BWSnapshot


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
    RESV_BLOCK = ResvBlockSteady
    OFFER_BLOCK = OfferBlockSteady

    def _parse(self, raw):
        data, req = self._parse_start(raw)
        self.path_ids.append(self._parse_path_id(data))
        self._update_idxes()
        if not self.setup:
            self.active_blocks.append(
                self._parse_block(data, self.path_lens[0]))
        self._parse_end(data, req)

    @classmethod
    def setup_from_values(cls, req_info, total_hops, path_id,
                          setup=True):  # pragma: no cover
        """Construct a setup request header."""
        inst = cls()
        inst.setup = setup
        inst.total_hops = total_hops
        inst.path_ids = [path_id]
        inst.req_block = ResvBlockSteady.from_values(req_info, inst.total_hops)
        inst._parse_src_ia()
        inst._set_size()
        return inst

    @classmethod
    def use_from_values(cls, path_id, block):  # pragma: no cover
        """Construct a header to use the supplied reservation block."""
        inst = cls()
        inst.path_ids = [path_id]
        inst.total_hops = block.num_hops
        inst.switch_resv(block)
        inst._parse_src_ia()
        return inst

    @staticmethod
    def mk_path_id(isd_as):  # pragma: no cover
        """Generate a steady path ID."""
        return isd_as.pack() + os.urandom(SIBRA_STEADY_ID_LEN - isd_as.LEN)

    def pack(self):  # pragma: no cover
        raw = self._pack_start()
        raw.append(struct.pack("!Bxx", self.total_hops))
        return self._pack_end(raw)

    def teardown(self):  # pragma: no cover
        """Shut down the current reservation."""
        # FIXME(kormat): not implemented yet in sibra state.
        req_info = ResvInfoSteady.from_values(0, BWSnapshot(), 0)
        self.req_block = ResvBlockSteady.from_values(req_info, self.total_hops)
        self._set_size()

    def get_next_ifid(self):  # pragma: no cover
        if self.setup:
            # Steady setup packets have no active SOFs
            return None
        return super().get_next_ifid()

    def _req_add(self, state, idx, bwsnap, exp_tick):  # pragma: no cover
        return state.add_steady(
            self.path_ids[0], idx, bwsnap, exp_tick, self.accepted, self.setup)

    def _add_hop(self, key, spkt=None):
        """
        Handle adding an SOF to a request block

        Normally the interface information is in the active SOF field, but
        steady setup packets are special as they travel along a SCION path, so
        extract the interfaces from there.
        """
        if not self.setup:
            super()._add_hop(key)
            return
        iof = spkt.path.get_iof()
        hof = spkt.path.get_hof()
        if iof.cons_dir_flag:
            if1, if2 = hof.ingress_if, hof.egress_if
        else:
            if1, if2 = hof.egress_if, hof.ingress_if
        prev_raw = self._get_prev_raw(req=True)
        self.req_block.add_hop(if1, if2, prev_raw, key, self.path_ids)
