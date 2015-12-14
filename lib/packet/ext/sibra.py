# Copyright 2015 ETH Zurich
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
:mod:`sibra` --- SIBRA extension for SCION
==========================================
"""
# Stdlib
import os
import struct
from binascii import hexlify

# SCION
from lib.crypto.symcrypto import cbcmac
from lib.errors import SCIONParseError
from lib.packet.ext_hdr import HopByHopExtension, HopByHopType
from lib.util import Raw, calc_padding

#: Number of seconds per sibra interval
SIBRA_INTERVAL = 4
LINE_LEN = HopByHopExtension.LINE_LEN


class SibraExt(HopByHopExtension):
    """
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
    """
    NAME = "SibraExt"
    EXT_TYPE = HopByHopType.SIBRA
    STEADY_ID_LEN = 8
    EPHEMERAL_ID_LEN = 8
    MIN_LEN = HopByHopExtension.SUBHDR_LEN
    SIBRA_VERSION = 0
    FLAG_PATH_SETUP = 0b10000000
    FLAG_REQ = 0b01000000
    FLAG_ACCEPT = 0b00100000
    FLAG_ERROR = 0b00010000
    FLAG_STEADY = 0b00001000
    FLAG_FWD = 0b00000100
    FLAG_VERSION = 0b00000011

    def __init__(self, raw=None):  # pragma: no cover
        super().__init__()
        # Flags:
        self.setup = None
        self.req = None
        self.accepted = True
        self.error = False
        self.steady = True
        self.fwd = True
        self.version = self.SIBRA_VERSION
        # Rest of extension:
        self.curr_hop = 0
        self.path_ids = []
        self.active_blocks = []
        self.req_block = None
        # Metadata
        self.total_hops = 0

        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, "SibraExt", self.MIN_LEN, min_=True)
        self._parse_flags(data.pop(1))
        self.curr_hop = data.pop(1)
        path_lens = struct.unpack("!BBB", data.pop(3))
        self.total_hops = sum(path_lens)
        self.path_ids.append(self._parse_path_id(data, self.steady))
        if not self.steady:
            # Ephemeral packets contain 1-3 steady path IDs before the active
            # reservation block(s)
            for plen in path_lens:
                if not plen:
                    break
                self.path_ids.append(self._parse_path_id(data, steady=True))
        if not (self.setup and self.steady):
            # All non-steady-setup packets have an 1+ active reservation blocks
            for plen in path_lens:
                if not plen:
                    break
                self.active_blocks.append(self._parse_block(data, plen))
        if self.req:
            if self.accepted:
                self.req_block = self._parse_block(data, self.total_hops)
            else:
                self.req_block = self._parse_offers_block(data)
        if len(data):
            raise SCIONParseError("%s bytes left when parsing SibraExt: %s" % (
                len(data), hexlify(data.get())))

    def _parse_flags(self, flags):
        self.setup = bool(flags & self.FLAG_PATH_SETUP)
        self.req = bool(flags & self.FLAG_REQ)
        self.accepted = bool(flags & self.FLAG_ACCEPT)
        self.error = bool(flags & self.FLAG_ERROR)
        self.steady = bool(flags & self.FLAG_STEADY)
        self.fwd = bool(flags & self.FLAG_FWD)
        self.version = flags & self.FLAG_VERSION
        if self.setup:
            assert self.req
        assert self.version == self.SIBRA_VERSION

    def _parse_path_id(self, data, steady=False):  # pragma: no cover
        if steady:
            return data.pop(self.STEADY_ID_LEN)
        return data.pop(self.EPHEMERAL_ID_LEN)

    def _parse_block(self, data, num_hops):
        block_len = (1 + num_hops) * LINE_LEN
        return ResvBlock(data.pop(block_len))

    def _parse_offers_block(self, data):  # pragma: no cover
        block = OfferBlock(data.get())
        data.pop(len(block))
        return block

    @classmethod
    def from_values(cls):
        raise NotImplementedError

    @classmethod
    def steady_from_values(cls, isd_ad, req_info, total_hops):
        inst = cls()
        inst.setup = True
        inst.req = True
        inst.path_ids.append(isd_ad.pack() + os.urandom(inst.STEADY_ID_LEN))
        inst.req_block = ResvBlock.from_values(req_info, num_hops=total_hops)
        return inst

    @classmethod
    def ephemeral_from_values(cls, isd_ad, req_info, steady_ids, steady_blocks):
        assert len(steady_ids) == len(steady_blocks)
        inst = cls()
        inst.setup = True
        inst.req = True
        inst.steady = False
        inst.path_ids.append(isd_ad.pack() + os.urandom(inst.EPHEMERAL_ID_LEN))
        inst.path_ids.extend(steady_ids)
        inst.active_blocks = steady_blocks
        total_hops = sum([b.num_hops for b in steady_blocks])
        inst.req_block = ResvBlock.from_values(req_info, num_hops=total_hops)
        return inst

    def pack(self):
        raw = []
        raw.append(self._pack_flags())
        raw.append(struct.pack("!B", self.curr_hop))
        path_lens = [0, 0, 0]
        if self.active_blocks:
            for i, active in enumerate(self.active_blocks):
                path_lens[i] = active.num_hops
        else:
            path_lens[0] = self.total_hops
        raw.append(struct.pack("!BBB", *path_lens))
        raw.extend(self.path_ids)
        for block in self.active_blocks:
            raw.append(block.pack())
        if self.req_block:
            raw.append(self.req_block.pack())
        result = b"".join(raw)
        assert (len(result) + 3) % LINE_LEN == 0
        return result

    def _pack_flags(self):
        flags = 0
        if self.setup:
            flags |= self.FLAG_PATH_SETUP
        if self.req:
            flags |= self.FLAG_REQ
        if self.accepted:
            flags |= self.FLAG_ACCEPT
        if self.error:
            flags |= self.FLAG_ERROR
        if self.steady:
            flags |= self.FLAG_STEADY
        if self.fwd:
            flags |= self.FLAG_FWD
        flags |= self.version
        return flags

    def _pack_ephemeral_setup(self):
        raw = []
        for id_, block in zip(self.path_ids[1:], self.active_blocks):
            raw.append(id_)
            raw.append(block.pack())
        return b"".join(raw)

    def process(self, spkt):
        pass


class ResvInfo(object):
    LEN = LINE_LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.exp = None
        self.bw_fwd = None
        self.bw_rev = None
        self.index = None
        self.fail_hop = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, "ResvInfo", self.LEN)
        self.exp = struct.unpack("!I", data.pop(4))[0] * SIBRA_INTERVAL
        self.bw_fwd = data.pop(1)
        self.bw_rev = data.pop(1)
        self.index = data.pop(1) >> 4
        self.fail_hop = data.pop(1)

    @classmethod
    def from_values(cls, exp, bw_fwd=0, bw_rev=0, index=0,
                    fail_hop=0):  # pragma: no cover
        inst = cls()
        inst.exp = int(exp / SIBRA_INTERVAL)
        inst.bw_fwd = bw_fwd
        inst.bw_rev = bw_rev
        inst.index = index
        inst.fail_hop = fail_hop
        return inst

    def pack(self):
        raw = []
        raw.append(struct.pack("!I", int(self.exp / SIBRA_INTERVAL)))
        raw.append(struct.pack("!BB", self.bw_fwd, self.bw_rev))
        raw.append(struct.pack("!BB", self.index << 4, self.fail_hop))
        return b"".join(raw)

    def __len__(self):  # pragma: no cover
        return self.LEN


class ResvBlock(object):
    MIN_LEN = ResvInfo.LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.info = None
        self.sofs = []
        self.num_hops = 0
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, "ResvBlock", self.MIN_LEN, min_=True)
        self.info = ResvInfo(data.pop(ResvInfo.LEN))
        self.num_hops = len(data) // SibraOpaqueField.LEN
        while data:
            raw_sof = data.pop(SibraOpaqueField.LEN)
            if raw_sof == bytes(SibraOpaqueField.LEN):
                break
            self.sofs.append(SibraOpaqueField(raw_sof))

    @classmethod
    def from_values(cls, info, sofs=None, num_hops=None):  # pragma: no cover
        inst = cls()
        inst.info = info
        inst.sofs = sofs or []
        inst.num_hops = num_hops or len(inst.sofs)
        assert num_hops >= len(inst.sofs)

    def pack(self, path_ids):
        raw = []
        raw.append(self.info.pack())
        for i, sof in enumerate(self.sofs):
            prev_sof = None
            if i > 0:
                prev_sof = self.sofs[i-1]
            raw.append(sof.pack(self.info, path_ids, prev_sof))
        for i in range(len(self.sofs), self.num_hops):
            raw.append(bytes(SibraOpaqueField.LEN))
        return b"".join(raw)

    def __len__(self):  # pragma: no cover
        return (1 + self.num_hops) * LINE_LEN


class OfferBlock(object):
    MIN_LEN = ResvInfo.LEN
    OFFER_LEN = 2
    OFFERS_PER_LINE = LINE_LEN // OFFER_LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.info = None
        self.offers = []
        self.offer_hops = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, "OfferBlock", self.MIN_LEN, min_=True)
        self.info = ResvInfo(data.pop(ResvInfo.LEN))
        self.offer_hops = len(data) // self.OFFER_LEN
        while data:
            offer = struct.unpack("!BB", data.pop(2))
            if offer == (0, 0):
                break
            self.offers.append(offer)

    @classmethod
    def from_values(cls, info, offer_hops, bw_fwd=0, bw_rev=0):
        inst = cls()
        inst.info = info
        inst.offers.append((bw_fwd, bw_rev))
        inst.offer_hops = offer_hops
        # Pad number of offer hops to a full line
        inst.offer_hops += calc_padding(offer_hops, cls.OFFERS_PER_LINE)
        return inst

    def pack(self):
        raw = []
        raw.append(self.info.pack())
        for offer in self.offers:
            raw.append(struct.pack("!BB", *offer))
        for i in range(len(self.offers), self.offer_hops):
            raw.append(bytes(self.OFFER_LEN))
        result = b"".join(raw)
        assert len(result) % LINE_LEN == 0
        assert len(result) == len(self)
        return result

    def __len__(self):  # pragma: no cover
        return ResvInfo.LEN + self.offer_hops * self.OFFER_LEN


class SibraOpaqueField(object):
    MAC_LEN = 4
    IF_LEN = 2
    LEN = IF_LEN * 2 + MAC_LEN
    # Steady + ephemeral path:
    MAX_PATH_IDS_LEN = SibraExt.STEADY_ID_LEN + SibraExt.EPHEMERAL_ID_LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.ingress = None
        self.egress = None
        self.mac = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, "SibraOpaqueField", self.LEN)
        self.ingress, self.egress = struct.unpack(
            "!HH", data.pop(self.IF_LEN * 2))
        self.mac = struct.unpack("!I", data.pop(self.MAC_LEN))[0]

    @classmethod
    def from_values(cls, ingress=0, egress=0, mac=None):  # pragma: no cover
        inst = cls()
        inst.ingress = ingress
        inst.egress = egress
        inst.mac = mac or bytes(cls.MAC_LEN)
        return inst

    def pack(self):
        raw = []
        raw.append(struct.pack("!HH", self.ingress, self.egress))
        raw.append(struct.pack("!I", self.mac))
        return b"".join(raw)

    def calc_mac(self, key, info, path_ids, prev_raw=None):
        raw = []
        raw.append(struct.pack("!HH", self.ingress, self.egress))
        # Don't include the last byte of the ResvInfo object
        raw.append(info.pack()[:info.LEN-1] + bytes(1))
        ids_len = 0
        for id_ in path_ids:
            ids_len += len(id_)
            raw.append(id_)
        # Pad path IDs with 0's to give constant length
        raw.append(bytes(self.MAX_PATH_IDS_LEN - ids_len))
        raw.append(prev_raw or bytes(self.LEN))
        to_mac = b"".join(raw)
        assert len(to_mac) == (self.IF_LEN * 2 + ResvInfo.LEN +
                               self.MAX_PATH_IDS_LEN + self.LEN)
        return cbcmac(key, b"".join(raw))[:self.MAC_LEN]

    def __len__(self):  # pragma: no cover
        return self.LEN


def sibra_ext_handler(**kwargs):
    ext = kwargs["ext"]
    spkt = kwargs["spkt"]
    ext.process(spkt)
