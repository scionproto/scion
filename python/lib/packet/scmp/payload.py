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
:mod:`payload` --- SCMP payload
===============================
"""
# Stdlib
import struct

# SCION
from lib.defines import LINE_LEN
from lib.packet.packet_base import Serializable
from lib.packet.scmp.info import parse_scmp_info, build_scmp_info
from lib.packet.scmp.types import SCMPIncParts
from lib.packet.scmp.util import scmp_get_inc_parts
from lib.types import L4Proto
from lib.util import Raw, calc_padding, hex_str


class SCMPPayload(Serializable):
    """
    Payload structure:
        - meta data to allow parsing of the rest
        - (optional) info related to the specific SCMP class/type.
        - (optional) original common header
        - (optional) original path
        - (optional) original extensions
        - (optional) original l4 header, if any.
    All sections are padded to a multiple of 8B, all lengths in the metadata are
    multiples of 8B.
    """
    NAME = "SCMPPayload"
    # Info len(1B), Cmn hdr len (1B), Addr hdr len (1B), Path hdr len (1B), Ext
    # hdrs len (1B), L4 hdr len (1B), L4 proto (1B)
    STRUCT_FMT = "!BBBBBBBx"
    META_LEN = struct.calcsize(STRUCT_FMT)

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param tuple raw:
            Tuple of (int, int, bytes) for the SCMP class and type codes, and
            the raw SCMP payload, respectively.
        """
        self.info = None
        self._cmn_hdr = b""
        self._addrs = b""
        self._path = b""
        self._exts = b""
        self._l4_hdr = b""
        self.l4_proto = None
        if raw:
            class_, type_, raw = raw
            self._parse(class_, type_, raw)

    def _parse(self, class_, type_, raw):
        data = Raw(raw, self.NAME)
        (info_len, cmn_hdr_len, addrs_len, path_len, exts_len, l4_len,
         self.l4_proto) = struct.unpack(
             self.STRUCT_FMT, data.pop(self.META_LEN))
        self.info = parse_scmp_info(class_, type_,
                                    data.pop(info_len * LINE_LEN))
        self._cmn_hdr = data.pop(cmn_hdr_len * LINE_LEN)
        self._addrs = data.pop(addrs_len * LINE_LEN)
        self._path = data.pop(path_len * LINE_LEN)
        self._exts = data.pop(exts_len * LINE_LEN)
        self._l4_hdr = data.pop(l4_len * LINE_LEN)

    @classmethod
    def from_values(cls, info=None, cmn_hdr=b"", addrs=b"", path=b"", exts=b"",
                    l4_hdr=b"", l4_proto=L4Proto.NONE):  # pragma: no cover
        inst = cls()
        inst.info = info
        inst._cmn_hdr = cmn_hdr
        inst._addrs = addrs
        inst._path = path
        inst._exts = exts
        inst._l4_hdr = l4_hdr
        inst.l4_proto = l4_proto
        return inst

    @classmethod
    def from_pkt(cls, class_, type_, pkt, *args, **kwargs):
        inst = cls()
        inst.info = build_scmp_info(class_, type_, pkt, *args, **kwargs)
        inc_list = scmp_get_inc_parts(class_, type_)
        if SCMPIncParts.CMN in inc_list:
            inst._cmn_hdr = pkt.cmn_hdr.pack()
        if SCMPIncParts.ADDRS in inc_list:
            inst._addrs = pkt.addrs.pack()
        if SCMPIncParts.PATH in inc_list:
            inst._path = pkt.path.pack()
        if SCMPIncParts.EXTS in inc_list:
            inst._exts = pkt.pack_exts()
        if SCMPIncParts.L4 in inc_list:
            if pkt.l4_hdr:
                inst._l4_hdr = pkt.l4_hdr.pack(b"")
                inst.l4_proto = pkt.l4_hdr.TYPE
            else:
                payload = pkt.get_payload()
                pld = payload.pack()[:LINE_LEN * 4]
                inst._l4_hdr = pld + bytes(calc_padding(len(pld), LINE_LEN))
                inst.l4_proto = pkt.get_l4_proto()
        else:
            inst.l4_proto = L4Proto.NONE
        return inst

    def pack(self):
        def _add(data, len_):
            assert len(data) == len_
            assert len(data) % LINE_LEN == 0
            raw.append(data)
        raw = []
        _add(self._pack_meta(), self.META_LEN)
        if self.info:
            _add(self.info.pack(), len(self.info))
        _add(self._cmn_hdr, len(self._cmn_hdr))
        _add(self._addrs, len(self._addrs))
        _add(self._path, len(self._path))
        _add(self._exts, len(self._exts))
        _add(self._l4_hdr, len(self._l4_hdr))
        packed = b"".join(raw)
        assert len(packed) == len(self), "packed: %s claimed: %s" % (
            len(packed), len(self))
        return b"".join(raw)

    def _pack_meta(self):
        def blk_len(blk):
            assert len(blk) % LINE_LEN == 0
            values.append(len(blk) // LINE_LEN)
        values = []
        blocks = [self._cmn_hdr, self._addrs, self._path, self._exts,
                  self._l4_hdr]
        if self.info:
            blk_len(self.info)
        else:
            values.append(0)
        for blk in blocks:
            blk_len(blk)
        values.append(self.l4_proto)
        return struct.pack(self.STRUCT_FMT, *values)

    def __len__(self):  # pragma: no cover
        l = self.META_LEN
        if self.info:
            l += len(self.info)
        for i in (self._cmn_hdr, self._addrs, self._path, self._exts,
                  self._l4_hdr):
            l += len(i)
        return l

    def __str__(self):
        def hdr_str(name, val):
            if not val:
                return
            ret.append("  %s(%dB): %s" % (name, len(val), hex_str(val)))
        ret = []
        ret.append("%s(%dB): L4 proto: %s" % (
            self.NAME, len(self), L4Proto.to_str(self.l4_proto)))
        if self.info:
            ret.append("  %s" % self.info)
        hdr_str("Common Header", self._cmn_hdr)
        hdr_str("Address Header", self._addrs)
        hdr_str("Path Header", self._path)
        hdr_str("Extension Headers", self._exts)
        hdr_str("L4 Header", self._l4_hdr)
        return "\n".join(ret)
