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
:mod:`ephemeral` --- SIBRA Ephemeral path extension
===================================================
"""
# Stdlib
import os
import struct

# SCION
from lib.defines import SIBRA_EPHEMERAL_ID_LEN
from lib.sibra.ext.ext import SibraExtBase
from lib.sibra.ext.offer import OfferBlockEphemeral
from lib.sibra.ext.resv import ResvBlockEphemeral
from lib.types import RouterFlag


class SibraExtEphemeral(SibraExtBase):
    """
    SIBRA Ephemeral path extension header.

    Ephemeral paths are short-lived (by default) paths set up by endhosts to
    provide bandwidth availability guarantees for connections to a specified
    destination. Ephemeral paths are built on top of steady paths, and hence
    have multiple path IDs associated with them: an ephemeral path ID to
    identify this reservation, and up to 3 steady path IDs to identify the
    steady up/core/down paths that it is built on. This also means that
    ephemeral setup packets contain an active block from each of the steady
    paths they traverse.
    """
    NAME = "SibraExtEphemeral"
    STEADY = False
    RESV_BLOCK = ResvBlockEphemeral
    OFFER_BLOCK = OfferBlockEphemeral

    def _parse(self, raw):
        data, req = self._parse_start(raw)
        self.path_ids.append(self._parse_path_id(data, False))
        self._update_idxes()
        # Ephemeral packets contain 1-3 steady path IDs, ephemeral /setup/
        # packets also contain the same number of active reservation block(s)
        for plen in self.path_lens:
            if not plen:
                break
            self.path_ids.append(self._parse_path_id(data))
        self.active_blocks = self._parse_active_blocks(data)
        self._parse_end(data, req)

    def _parse_active_blocks(self, data):
        if not self.setup:
            # Ephemeral non-setup packets have a single active block
            return [self._parse_block(data, self.total_hops)]
        # Ephemeral setup packets have 1-3 active blocks
        ret = []
        for plen in self.path_lens:
            if not plen:
                break
            ret.append(self._parse_block(data, plen))
        return ret

    @classmethod
    def setup_from_values(cls, req_info, path_id, steady_ids,
                          steady_blocks):
        inst = cls()
        inst.setup = True
        inst.steady = False
        for i, b in enumerate(steady_blocks):
            inst.path_lens[i] = b.num_hops
        inst._calc_total_hops()
        inst.path_ids = [path_id] + steady_ids
        inst.active_blocks = steady_blocks
        inst.req_block = ResvBlockEphemeral.from_values(
            req_info, inst.total_hops)
        inst._parse_src_ia()
        inst._set_size()
        return inst

    @classmethod
    def use_from_values(cls, path_ids, path_lens, block,
                        req_info=None):  # pragma: no cover
        inst = cls()
        inst.path_ids = path_ids
        for i, len_ in enumerate(path_lens):
            inst.path_lens[i] = len_
        inst._calc_total_hops()
        assert inst.total_hops == block.num_hops
        inst._parse_src_ia()
        if req_info:
            inst.req_block = ResvBlockEphemeral.from_values(
                req_info, inst.total_hops)
        inst.switch_resv(block)
        return inst

    @staticmethod
    def mk_path_id(isd_as):  # pragma: no cover
        """Generate an ephemeral path ID."""
        return isd_as.pack() + os.urandom(SIBRA_EPHEMERAL_ID_LEN - isd_as.LEN)

    def pack(self):  # pragma: no cover
        raw = self._pack_start()
        raw.append(struct.pack("!BBB", *self.path_lens))
        return self._pack_end(raw)

    def _calc_total_hops(self):
        """Calculate the total number of hops from the path lengths."""
        count = 0
        for plen in self.path_lens:
            if not plen:
                break
            count += 1
        # Compensate for cross-over hops
        self.total_hops = sum(self.path_lens) - count + 1

    def _update_idxes(self):
        """
        Update the current block/relative SOF indexes, and the current hop,
        based on the absolute SOF index.
        """
        if not self.setup:
            super()._update_idxes()
            return
        s_idx = self.sof_idx
        # Find the current active block, and the relative SOF index into it.
        for b_idx, plen in enumerate(self.path_lens):
            if s_idx < plen:
                break
            s_idx -= plen
        else:
            # FIXME(kormat): needs exception
            # Should never reach here.
            assert False
        self.block_idx = b_idx
        self.rel_sof_idx = s_idx
        # Compensate for cross-over hops
        self.curr_hop = self.sof_idx - b_idx

    def _process_setup(self, meta):
        super()._process_setup(meta)
        if not meta.from_local_as:
            # Handle block switching on ingress at cross-over hops
            self._setup_switch_block()
        next_ifid = self.get_next_ifid()
        if next_ifid:
            return [(RouterFlag.FORWARD, next_ifid)]
        return [(RouterFlag.DELIVER,)]

    def _setup_switch_block(self):
        """
        Handles switching the active block at cross-over hops during ephemeral
        setup. Only called on ingress into an AS.
        """
        block = self.active_blocks[self.block_idx]
        if (self.fwd and self.block_idx < (len(self.active_blocks) - 1) and
                self.rel_sof_idx == (block.num_hops - 1)):
            # Forward, not last block, last SOF of current block: switch to
            # next block
            self.sof_idx += 1
            self._update_idxes()
        elif (not self.fwd and self.block_idx > 0 and
                self.rel_sof_idx == 0):
            # Reverse, not first block, first SOF of current block: switch
            # to previous block
            self.sof_idx -= 1
            self._update_idxes()

    def _req_add(self, state, idx, bwsnap, exp_tick):  # pragma: no cover
        return state.add_ephemeral(
            self.path_ids[0], self.path_ids[1 + self.block_idx], idx,
            bwsnap, exp_tick, self.accepted, self.setup)

    def _add_hop(self, key, _=None):
        """
        Add a SIBRA opaque field to the current request block.

        If the packet is not at a cross-over hop, use the ingress/egress
        interface IDs from the current active SOF. Else use the ingress ID from
        the previous SOF, and the egress ID from the current SOF.
        """
        if not self.setup:
            super()._add_hop(key)
            return
        curr_block = self.active_blocks[self.block_idx]
        curr_sof = curr_block.sofs[self.rel_sof_idx]
        if self.block_idx > 0 and self.rel_sof_idx == 0:
            # Just switched to a new steady block, use the ingress field
            # from the last SOF of the previous block
            prev_block = self.active_blocks[self.block_idx - 1]
            prev_sof = prev_block.sofs[-1]
            ingress, _ = self._get_ifids(prev_sof, prev_block.info.fwd_dir)
            _, egress = self._get_ifids(curr_sof, curr_block.info.fwd_dir)
        else:
            ingress, egress = self._get_ifids(curr_sof, curr_block.info.fwd_dir)
        prev_raw = self._get_prev_raw(req=True)
        self.req_block.add_hop(ingress, egress, prev_raw, key, self.path_ids)

    def _get_ifids(self, sof, fwd_dir):  # pragma: no cover
        if fwd_dir:
            return sof.ingress, sof.egress
        return sof.egress, sof.ingress

    def _verify_sof(self, key):
        """Verify the current SOF field."""
        path_ids = self.path_ids
        if self.setup:
            # Ephemeral setup packets have active steady reservation blocks,
            # which need to be verified against only their own path ID.
            path_ids = [self.path_ids[1 + self.block_idx]]
        return super()._verify_sof(key, path_ids)
