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
import struct
from binascii import hexlify

# SCION
from lib.defines import (
    SIBRA_STEADY_ID_LEN,
    SIBRA_EPHEMERAL_ID_LEN,
)
from lib.errors import SCIONParseError
from lib.packet.ext_hdr import HopByHopExtension
from lib.sibra.ext.resv import ResvBlockSteady, ResvBlockEphemeral
from lib.sibra.ext.offer import OfferBlockSteady, OfferBlockEphemeral
from lib.types import ExtHopByHopType
from lib.util import Raw

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
    | xxxxxxxxxxxxxxxxxxxxxxxx | Flags  |Curr hop|P0 hops |P1 hops |P2 hops |
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

    - Curr hop indicates where on the SIBRA path the packet currently is.
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

    def __init__(self, raw=None):  # pragma: no cover
        super().__init__()
        # Flags (except request flag):
        self.setup = None
        self.accepted = True
        self.error = False
        self.steady = self.STEADY
        self.fwd = True
        self.version = SIBRA_VERSION
        # Rest of extension:
        self.curr_hop = 0
        self.path_ids = []
        self.active_blocks = []
        # Acts as request flag
        self.req_block = None
        # Metadata
        self.path_lens = []
        self.total_hops = 0

        if raw:
            self._parse(raw)

    def _parse_start(self, raw):
        """
        Parse the first line of the extension header, which is common between
        steady and ephemeral reservations.
        """
        super()._parse(raw)
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        req = self._parse_flags(data.pop(1))
        self.curr_hop = data.pop(1)
        self.path_lens = struct.unpack("!BBB", data.pop(3))
        self.total_hops = sum(self.path_lens)
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
                len(data), self.NAME, hexlify(data.get())))

    def _parse_flags(self, flags):
        """
        Parse the header flags field
        """
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
        """
        Read a path ID
        """
        if steady:
            return data.pop(SIBRA_STEADY_ID_LEN)
        return data.pop(SIBRA_EPHEMERAL_ID_LEN)

    def _parse_block(self, data, num_hops, steady):
        """
        Parse a reservation block
        """
        block_len = (1 + num_hops) * self.LINE_LEN
        block = data.pop(block_len)
        if steady:
            return ResvBlockSteady(block)
        else:
            return ResvBlockEphemeral(block)

    def _parse_offers_block(self, data):  # pragma: no cover
        """
        Parse the offers block
        """
        if self.steady:
            block = OfferBlockSteady(data.get())
        else:
            block = OfferBlockEphemeral(data.get())
        data.pop(len(block))
        return block

    def _pack_start(self):  # pragma: no cover
        """
        Pack the extension flags and the current hop
        """
        raw = []
        raw.append(self._pack_flags())
        raw.append(struct.pack("!B", self.curr_hop))
        return raw

    def _pack_end(self, raw):
        """
        Pack the active and request/offer blocks
        """
        raw.extend(self.path_ids)
        for block in self.active_blocks:
            raw.append(block.pack())
        if self.req_block:
            raw.append(self.req_block.pack())
        result = b"".join(raw)
        self._check_len(result)
        return result

    def _pack_flags(self):
        """
        Pack the extension flags
        """
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

    def reverse(self):
        """
        Reverse the extension header
        """
        if self.setup and self.accepted and not self.fwd:
            # This is an accepted sibra setup reply packet, so configure for
            # use.
            self.setup = False
        self.fwd = not self.fwd

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

    def process(self, state, spkt, from_local_ad, key):
        """
        Process an extension header on a packet. `dir_fwd` is used to indicate
        the direction of travel relative to the local node. Forward means the
        packet is at an egress router, reverse means it's at an ingress router.
        """
        dir_fwd = True
        if self.fwd != from_local_ad:
            dir_fwd = False
        flags = self._process(state, spkt, dir_fwd, key)
        if from_local_ad:
            # Only increment curr_hop on egress from an AD.
            self.curr_hop += 1 if self.fwd else -1
        return flags

    def _add_hop(self, key, path_ids):  # pragma: no cover
        """
        Add a SIBRA opaque field to the current request block, reading the
        ingress/egress interface IDs from the current active SOF.

        This is called from child classes.
        """
        sof = self.active_sof()
        self.req_block.add_hop(sof.ingress, sof.egress, key, path_ids)

    def active_sof(self):
        """
        Find the current active SibraOpaqueField, by using the current hop and
        the path lengths to index into the appropriate active reservation block.
        """
        hops = self.curr_hop
        for i, plen in enumerate(self.path_lens):
            # FIXME(kormat): needs exception
            assert plen == len(self.active_blocks[i].sofs)
            if hops < plen:
                return self.active_blocks[i].sofs[hops]
            hops -= plen

    def switch_resv(self, blocks):
        """
        Switch to the reservation in the specified blocks
        """
        self.setup = False
        self.path_lens = [0, 0, 0]
        for i, b in enumerate(blocks):
            # FIXME(kormat): needs exception
            assert b.num_hops == len(b.sofs)
            self.path_lens[i] = b.num_hops
        # Total hops cannot change
        assert sum(self.path_lens) == self.total_hops
        self.active_blocks = blocks
        self._set_size()

    def get_min_offer(self):
        """
        Find the minimum bandwidth offered in both directions
        """
        return self.req_block.get_min(self.total_hops)

    def __str__(self):
        tmp = ["%s(%dB):" % (self.NAME, len(self))]
        tmp.append(
            "  Current hop: %s (Total: %s) Flags: setup:%s request:%s "
            "accepted:%s error:%s steady:%s forward:%s version:%s" %
            (self.curr_hop, self.total_hops, self.setup, bool(self.req_block),
             self.accepted, self.error, self.steady, self.fwd, self.version))
        type_ = "Steady" if self.steady else "Ephemeral"
        tmp.append("  %s path ID: %s" %
                   (type_, hexlify(self.path_ids[0]).decode("ascii")))
        for i, path_id in enumerate(self.path_ids[1:]):
            tmp.append("  Steady path %d ID: %s" %
                       (i, hexlify(path_id).decode("ascii")))
        for i, block in enumerate(self.active_blocks):
            tmp.append("  Active block %d:" % i)
            for line in str(block).splitlines():
                tmp.append("    %s" % line)
        if self.req_block:
            tmp.append("  Request block:")
            for line in str(self.req_block).splitlines():
                tmp.append("    %s" % line)
        return "\n".join(tmp)
