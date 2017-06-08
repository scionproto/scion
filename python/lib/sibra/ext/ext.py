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
:mod:`ext` --- SIBRA extension for SCION
========================================
"""
# Stdlib
import logging
import struct

# SCION
from lib.defines import (
    SIBRA_STEADY_ID_LEN,
    SIBRA_EPHEMERAL_ID_LEN,
)
from lib.errors import SCIONParseError
from lib.packet.ext_hdr import HopByHopExtension
from lib.packet.scion_addr import ISD_AS
from lib.sibra.ext.offer import OfferBlockSteady, OfferBlockEphemeral
from lib.sibra.ext.process import ProcessMeta
from lib.sibra.ext.resv import ResvBlockSteady, ResvBlockEphemeral
from lib.sibra.util import BWSnapshot
from lib.types import ExtHopByHopType, RouterFlag
from lib.util import Raw, hex_str

SIBRA_VERSION = 0
FLAG_PATH_SETUP = 0b10000000
FLAG_REQ = 0b01000000
FLAG_ACCEPT = 0b00100000
FLAG_ERROR = 0b00010000
FLAG_STEADY = 0b00001000
FLAG_FWD = 0b00000100
FLAG_VERSION = 0b00000011


class SibraExtBase(HopByHopExtension):
    """
    Base class for SIBRA packet extension. This class isn't used directly, but
    via SibraExtEphemeral and SibraExtSteady that inherit from it.

    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx | Flags  |SOF idx |P0 hops |P1 hops |P2 hops |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | <Path IDs>                                                            |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |...                                                                    |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | Reservation block                                                     |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | ...                                                                   |
    +                                                                       +

    The first byte contains the flag field. Its bits are allocated as follows:
      - (MSB) path setup flag:
          Set if packet is setting up a new SIBRA path.
      - request flag:
          Set if packet is requesting a reservation, i.e. setup or renewal.
      - accepted flag:
          Set if the reservation request has been accepted so far.
      - error flag:
          Set if an error has occurred.
      - steady flag:
          Set if this is a steady path, unset if this is an ephemeral path.
      - forward flag:
          Set if packet is travelling src->dest.
      - version (2b): SIBRA version, to be used as (SCION ver, SIBRA ver).

    - SOF idx indicates which is the current Sibra Opaque Field. The current hop
      location can be derived from this.
    - P* hops indicate how long each active reservation block is. Summed, they
      indicate the total number of hops in the path.
    - 1-4 Path IDs are used to identify the current path at the current point on
      its travel.
    - There can be multiple reservation blocks - between 0 and 3 active blocks,
      that are used to route the packet, and an optional request block.
    """
    EXT_TYPE = ExtHopByHopType.SIBRA
    MIN_LEN = HopByHopExtension.SUBHDR_LEN
    LINE_LEN = HopByHopExtension.LINE_LEN
    RESV_BLOCK = None

    def __init__(self, raw=None):  # pragma: no cover
        # Flags (except request flag):
        self.setup = None
        self.accepted = True
        self.error = False
        self.steady = self.STEADY
        self.fwd = True
        self.version = SIBRA_VERSION
        # Rest of extension:
        self.sof_idx = 0
        self.path_ids = []
        self.active_blocks = []
        # Acts as request flag
        self.req_block = None
        # Metadata
        self.path_lens = [0, 0, 0]
        self.curr_hop = 0
        self.total_hops = 0
        self.block_idx = 0
        self.rel_sof_idx = 0
        self.src_ia = None

        super().__init__(raw)

    def _parse_start(self, raw):
        """
        Parse the first line of the extension header, which is common between
        steady and ephemeral reservations.
        """
        super()._parse(raw)
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        req = self._parse_flags(data.pop(1))
        self.sof_idx = data.pop(1)
        self.path_lens = list(struct.unpack("!BBB", data.pop(3)))
        self._calc_total_hops()
        return data, req

    def _parse_end(self, data, req):
        """
        Parse the request block/offer block at the end of the header, if
        present.
        """
        if req:
            if self.accepted:
                self.req_block = self._parse_block(data, self.total_hops,
                                                   self.steady)
            else:
                self.req_block = self._parse_offers_block(data)
        if len(data):
            raise SCIONParseError("%s bytes left when parsing %s: %s" % (
                len(data), self.NAME, hex_str(data.get())))
        self._parse_src_ia()

    def _parse_src_ia(self):  # pragma: no cover
        self.src_ia = ISD_AS(self.path_ids[0][:ISD_AS.LEN])

    def _parse_flags(self, flags):
        """Parse the header flags field."""
        self.setup = bool(flags & FLAG_PATH_SETUP)
        req = bool(flags & FLAG_REQ)
        self.accepted = bool(flags & FLAG_ACCEPT)
        self.error = bool(flags & FLAG_ERROR)
        self.steady = bool(flags & FLAG_STEADY)
        self.fwd = bool(flags & FLAG_FWD)
        self.version = flags & FLAG_VERSION
        if self.setup:
            assert req
        assert self.version == SIBRA_VERSION
        assert self.steady == self.STEADY
        return req

    def _parse_path_id(self, data, steady=True):  # pragma: no cover
        """Read a path ID."""
        if steady:
            return data.pop(SIBRA_STEADY_ID_LEN)
        return data.pop(SIBRA_EPHEMERAL_ID_LEN)

    def _parse_block(self, data, num_hops, steady=True):
        """Parse a reservation block."""
        block_len = (1 + num_hops) * self.LINE_LEN
        block = data.pop(block_len)
        if steady:
            return ResvBlockSteady(block)
        return ResvBlockEphemeral(block)

    def _parse_offers_block(self, data):  # pragma: no cover
        """Parse the offers block."""
        if self.steady:
            block = OfferBlockSteady(data.get())
        else:
            block = OfferBlockEphemeral(data.get())
        data.pop(len(block))
        return block

    @classmethod
    def from_values(cls, *args, **kwargs):
        raise NotImplementedError

    def _pack_start(self):  # pragma: no cover
        """Pack the extension flags and the current SOF index."""
        raw = []
        raw.append(self._pack_flags())
        raw.append(struct.pack("!B", self.sof_idx))
        return raw

    def _pack_end(self, raw):
        """Pack the active and request/offer blocks."""
        raw.extend(self.path_ids)
        for block in self.active_blocks:
            raw.append(block.pack())
        if self.req_block:
            raw.append(self.req_block.pack())
        result = b"".join(raw)
        self._check_len(result)
        return result

    def _pack_flags(self):
        """Pack the extension flags."""
        flags = 0
        if self.setup:
            flags |= FLAG_PATH_SETUP
        if self.req_block:
            flags |= FLAG_REQ
        if self.accepted:
            flags |= FLAG_ACCEPT
        if self.error:
            flags |= FLAG_ERROR
        if self.steady:
            flags |= FLAG_STEADY
        if self.fwd:
            flags |= FLAG_FWD
        flags |= self.version
        assert self.version == SIBRA_VERSION
        assert self.steady == self.STEADY
        return bytes([flags])

    def _calc_total_hops(self):  # pragma: no cover
        """
        Calculate the total number of hops from the path lengths. Ephemeral
        setup packets have more complex calculations, and so override this
        method.
        """
        self.total_hops = self.path_lens[0]

    def _update_idxes(self):  # pragma: no cover
        """
        Update the current hop and relative SOF index from the current SOF
        index. Ephemeral setup packets have more complex calculations, and so
        override this method.
        """
        self.curr_hop = self.rel_sof_idx = self.sof_idx

    def _set_size(self):
        """
        Calculate the on-wire size of the extension header, padded to a multiple
        of LINE_LEN
        """
        extlen = 0
        for pid in self.path_ids:
            extlen += len(pid)
        for block in self.active_blocks:
            extlen += len(block)
        if self.req_block:
            extlen += len(self.req_block)
        self._init_size(extlen // self.LINE_LEN)

    def reverse(self):
        """Reverse the extension header."""
        if self.setup and self.accepted and not self.fwd:
            # This is an accepted sibra setup reply packet, so configure for
            # use.
            self.setup = False
        self.fwd = not self.fwd

    def renew(self, req_info):  # pragma: no cover
        """Renew the current reservation with the specified reservation info."""
        self.accepted = True
        self.req_block = self.RESV_BLOCK.from_values(req_info, self.total_hops)
        self._set_size()

    def switch_resv(self, block):
        """Switch to the reservation in the specified block."""
        # FIXME(kormat): needs exception
        assert block.num_hops == len(block.sofs)
        assert block.num_hops == self.total_hops
        self.setup = False
        self.active_blocks = [block]
        self._set_size()

    def get_min_offer(self):  # pragma: no cover
        """Find the minimum bandwidth offered in both directions."""
        return self.req_block.get_min(self.total_hops)

    def get_next_ifid(self):
        """
        Find the next interface ID for the current SOF. This depends both on the
        current packet direction (self.fwd), and the direction of the current
        active reservation (block.info.fwd_dir).
        """
        block = self.active_blocks[self.block_idx]
        sof = block.sofs[self.rel_sof_idx]
        if self.fwd == block.info.fwd_dir:
            return sof.egress
        return sof.ingress

    def process(self, state, spkt, from_local_as, key):
        """Process an extension header on a packet."""
        if not (self.steady and self.setup) and not self._verify_sof(key):
            # The packet is invalid, so tell the router the packet has been
            # handled, and let it be dropped.
            # (Steady setup packets don't have any active SOFs to verify)
            return [(RouterFlag.ERROR, "Invalid packet")]
        # The meta object encapsulates metadata # are needed by various
        # processing levels.
        meta = ProcessMeta(state, spkt, from_local_as, key, self.fwd)
        flags = self._process_blocks(meta)
        if from_local_as:
            # Only increment sof_idx on egress from an AS.
            self.sof_idx += 1 if self.fwd else -1
            self._update_idxes()
        return flags

    def _process_blocks(self, meta):
        """Process request/active blocks."""
        flags = []
        if self.setup:
            logging.debug("SIBRA setup. Steady? %s", self.steady)
            flags.extend(self._process_setup(meta))
            return flags
        if self.req_block:
            logging.debug("SIBRA renewal. Steady? %s", self.steady)
            flags.extend(self._process_renewal(meta))
        flags.extend(self._process_use(meta))
        return flags

    def _process_setup(self, meta):
        """
        Process a packet containing a setup request. If it's on the return trip,
        update the local SIBRA state appropriately.
        """
        if not self.fwd:
            # Request on return trip
            if self.accepted:
                meta.state.pend_confirm(self.path_ids[0], self.steady)
            else:
                # Reservation has been rejected by further along the path.
                meta.state.pend_remove(self.path_ids[0], self.steady)
        else:
            # Route packet as normal
            self._process_req(meta)
        return []

    def _process_renewal(self, meta):
        """
        Process a packet containing a reservation renewal. If it's on the return
        trip, update the local SIBRA state appropriately.
        """
        if not self.fwd:
            # Renewal return trip
            req_info = self.req_block.info
            if not self.accepted and req_info.fail_hop > self.curr_hop:
                meta.state.idx_remove(self.path_ids[0], req_info.index,
                                      self.steady)
        else:
            self._process_req(meta)
        return []

    def _process_req(self, meta):
        """
        Process a packet containing a request (setup or renewal) and handle
        success/denial appropriately.
        """
        req_info = self.req_block.info
        bwsnap = req_info.bw.to_snap()
        if not meta.dir_fwd:
            bwsnap.reverse()
        bw_hint = self._req_add(meta.state, req_info.index, bwsnap,
                                req_info.exp_tick)
        if self.accepted and not bw_hint:
            # Hasn't been previously rejected, and no suggested bandwidth from
            # _req_add, so the request is accepted.
            self._req_accepted(meta.dir_fwd, meta.key, meta.spkt)
        else:
            self._req_denied(meta.dir_fwd, bw_hint)

    def _process_use(self, meta):
        """
        Process a packet using a SIBRA reservation.
        Update the appropriate usage counters, and determine the next hop.
        """
        bw_used = BWSnapshot(len(meta.spkt) * 8)
        if not meta.dir_fwd:
            bw_used.reverse()
        logging.debug("SIBRA use (Steady? %s)", self.steady)
        if not meta.state.use(
                self.path_ids[0], self.active_blocks[self.block_idx].info.index,
                bw_used, self.steady):
            return [(RouterFlag.ERROR, "SIBRA packet rejected")]
        next_ifid = self.get_next_ifid()
        if next_ifid:
            return [(RouterFlag.FORWARD, next_ifid)]
        return [(RouterFlag.DELIVER,)]

    def _req_accepted(self, dir_fwd, key, spkt):  # pragma: no cover
        """
        Add a SOF to the request block, but only if one of these is true:
        - this is an egress hop
        - this is the ingress hop at the destination
        """
        if dir_fwd or (self.curr_hop == self.total_hops - 1):
            self._add_hop(key, spkt)

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
        assert self.curr_hop >= self.req_block.info.fail_hop
        if dir_fwd:
            # Req was already rejected, and this is on egress, so update the
            # offer that the ingress BR made.
            offer_hop = self.curr_hop - self.req_block.info.fail_hop
            curr_offer = self.req_block.offers[offer_hop]
            curr_offer.min(bw_hint)
        else:
            # Req was already rejected, and this is on ingress, so add a new
            # offer.
            self.req_block.add(self.curr_hop, bw_hint)

    def _reject_req(self, bw_hint):
        """Switch from a request block to an offer block."""
        logging.warning("SIBRA request failed, changing to offer block")
        req_info = self.req_block.info
        req_info.fail_hop = self.curr_hop
        self.accepted = False
        self.req_block = self.OFFER_BLOCK.from_values(
            req_info, self.total_hops - self.curr_hop)
        self.req_block.add(self.curr_hop, bw_hint)
        self._set_size()

    def _add_hop(self, key, _=None):  # pragma: no cover
        """
        Add a SIBRA opaque field to the current request block, reading the
        ingress/egress interface IDs from the current active SOF.
        """
        sof = self.active_blocks[self.block_idx].sofs[self.rel_sof_idx]
        prev_raw = self._get_prev_raw(req=True)
        self.req_block.add_hop(sof.ingress, sof.egress, prev_raw, key,
                               self.path_ids)

    def _get_prev_raw(self, req=False):
        """Get the packed value of the previous SOF."""
        if req:
            block = self.req_block
            s_idx = self.curr_hop
            assert s_idx < block.num_hops
        else:
            block = self.active_blocks[self.block_idx]
            s_idx = self.rel_sof_idx
            assert s_idx < block.num_hops
        if block.info.fwd_dir:
            if s_idx > 0:
                return block.sofs[s_idx - 1].pack()
        elif s_idx < (block.num_hops - 1):
            return block.sofs[s_idx + 1].pack()
        return None

    def _verify_sof(self, key, path_ids=None):
        """Verify the current SOF field."""
        if not path_ids:
            path_ids = self.path_ids
        block = self.active_blocks[self.block_idx]
        sof = block.sofs[self.rel_sof_idx]
        if sof.mac == sof.calc_mac(
                block.info, key, path_ids, self._get_prev_raw()):
            return True
        logging.error("MAC verification failed:\n%s", self)
        return False

    def _id_with_owner(self, id_):  # pragma: no cover
        return "%s (Owner: %s)" % (hex_str(id_), ISD_AS(id_[:ISD_AS.LEN]))

    def __str__(self):
        tmp = ["%s(%dB):" % (self.NAME, len(self))]
        tmp.append(
            "  SOF idx: %s Hop: %s (Total hops: %s) Flags: setup:%s "
            "request:%s accepted:%s error:%s steady:%s forward:%s version:%s" %
            (self.sof_idx, self.curr_hop, self.total_hops, self.setup,
             bool(self.req_block), self.accepted, self.error, self.steady,
             self.fwd, self.version))
        type_ = "Steady" if self.steady else "Ephemeral"
        tmp.append("  %s path ID: %s" % (
            type_, self._id_with_owner(self.path_ids[0])))
        for i, path_id in enumerate(self.path_ids[1:]):
            tmp.append("  Steady path %d ID: %s" % (
                i, self._id_with_owner(path_id)))
        for i, block in enumerate(self.active_blocks):
            tmp.append("  Active block %d:" % i)
            for line in str(block).splitlines():
                tmp.append("    %s" % line)
        if self.req_block:
            tmp.append("  Request block:")
            for line in str(self.req_block).splitlines():
                tmp.append("    %s" % line)
        return "\n".join(tmp)
