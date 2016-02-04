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
from lib.sibra.ext.resv import ResvBlockEphemeral


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

    def _parse(self, raw):
        data = self._parse_start(raw)
        self.path_ids.append(self._parse_path_id(data, False))
        # Ephemeral packets contain 1-3 steady path IDs, followed by the same
        # number of active reservation block(s)
        for plen in self.path_lens:
            if not plen:
                break
            self.path_ids.append(self._parse_path_id(data))
        for plen in self.path_lens:
            if not plen:
                break
            self.active_blocks.append(self._parse_block(data, plen), self.setup)
        self._parse_end(data)

    @classmethod
    def from_values(cls, isd_ad, req_info, steady_ids, steady_blocks):
        assert len(steady_ids) == len(steady_blocks)
        inst = cls()
        inst.setup = True
        inst.steady = False
        inst.path_ids.append(isd_ad.pack() +
                             os.urandom(SIBRA_EPHEMERAL_ID_LEN - isd_ad.LEN))
        inst.path_ids.extend(steady_ids)
        inst.active_blocks = steady_blocks
        inst.total_hops = sum([b.num_hops for b in steady_blocks])
        inst.req_block = ResvBlockEphemeral.from_values(
            req_info, inst.total_hops)
        inst._init_size(inst._calc_size() // cls.LINE_LEN)
        return inst

    def pack(self):
        raw = self._pack_start()
        path_lens = [0, 0, 0]
        for i, active in enumerate(self.active_blocks):
            path_lens[i] = active.num_hops
        raw.append(struct.pack("!BBB", *path_lens))
        return self._pack_end(raw)

    def _process(self, state, spkt, dir_fwd, key):
        if not self._verify_sof():
            # The packet is invalid, so tell the router the packet has been
            # handled, and let it be dropped.
            return True
