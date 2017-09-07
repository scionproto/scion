# Copyright 2014 ETH Zurich
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
:mod:`scion` --- SCION packets
==============================
"""
# Stdlib
import copy
import struct

# SCION
from lib.defines import LINE_LEN, MAX_HOPBYHOP_EXT, SCION_PROTO_VERSION
from lib.errors import SCIONIndexError, SCIONParseError
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.ext_util import parse_extensions
from lib.packet.host_addr import HostAddrInvalidType, haddr_get_type
from lib.packet.ctrl_pld import CtrlPayload
from lib.packet.opaque_field import OpaqueField
from lib.packet.packet_base import (
    Serializable,
    L4HeaderBase,
    PacketBase,
    PayloadRaw,
)
from lib.packet.path import SCIONPath, parse_path
from lib.packet.scion_addr import ISD_AS, SCIONAddr
from lib.packet.scion_l4 import parse_l4_hdr
from lib.packet.scmp.errors import (
    SCMPBadDstType,
    SCMPBadEnd2End,
    SCMPBadHOFOffset,
    SCMPBadHopByHop,
    SCMPBadHost,
    SCMPBadIOFOffset,
    SCMPBadPktLen,
    SCMPBadSrcType,
    SCMPBadVersion,
)
from lib.packet.scmp.ext import SCMPExt
from lib.packet.scmp.hdr import SCMPHeader
from lib.packet.scmp.payload import SCMPPayload
from lib.packet.svc import SVCType
from lib.types import (
    AddrType,
    ExtHopByHopType,
    ExtensionClass,
    L4Proto,
)
from lib.util import Raw, calc_padding


class SCIONCommonHdr(Serializable):
    """
    Encapsulates the common header for SCION packets.
    """
    NAME = "SCIONCommonHdr"
    LEN = 8

    def __init__(self, raw=None):  # pragma: no cover
        self.version = 0  # Version of SCION packet.
        self.dst_addr_type = None
        self.src_addr_type = None
        self.addrs_len = None  # Length of the address block
        self.total_len = None  # Total length of the packet.
        self.hdr_len = None  # Header length including the path.
        self._iof_idx = None  # Index of the current Info Opaque Field
        self._hof_idx = None  # Index of the current Hop Opaque Field
        self.next_hdr = None  # Type of the next hdr field (IP protocol numbers)
        super().__init__(raw)

    def _parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        data = Raw(raw, self.NAME, self.LEN)
        (types, self.total_len, self.hdr_len, iof_off, hof_off,
         self.next_hdr) = struct.unpack("!HHBBBB", data.pop())
        self.version = types >> 12
        if self.version != SCION_PROTO_VERSION:
            raise SCMPBadVersion("Unsupported SCION version: %s" % self.version)
        self.dst_addr_type = (types >> 6) & 0x3f
        self.src_addr_type = types & 0x3f
        self.addrs_len, _ = SCIONAddrHdr.calc_lens(
            self.dst_addr_type, self.src_addr_type)
        if self.hdr_len_bytes() < self.LEN + self.addrs_len:
            # Can't send an SCMP error, as there isn't enough information to
            # parse the path and the l4 header.
            raise SCIONParseError(
                "hdr_len (%sB) < common header len (%sB) + addrs len (%sB) " %
                (self.hdr_len_bytes(), self.LEN, self.addrs_len))
        if iof_off == hof_off == 0:
            self._iof_idx = self._hof_idx = 0
            return
        if iof_off == 0 or hof_off <= iof_off:
            raise SCIONParseError(
                "invalid CurrINF, CurrHF combination: (%s, %s) " % (iof_off, hof_off))
        first_of_offset = self.LEN + self.addrs_len
        # FIXME(kormat): NB this assumes that all OFs have the same length.
        self._iof_idx = (iof_off * LINE_LEN - first_of_offset) // OpaqueField.LEN
        self._hof_idx = (hof_off * LINE_LEN - first_of_offset) // OpaqueField.LEN

    @classmethod
    def from_values(cls, dst_type, src_type, next_hdr):
        """
        Returns a SCIONCommonHdr object with the values specified.

        :param int dst_type: Destination address type.
        :param int src_type: Source address type.
        :param int next_hdr: Next header type.
        """
        inst = cls()
        inst.dst_addr_type = dst_type
        inst.src_addr_type = src_type
        inst.addrs_len, _ = SCIONAddrHdr.calc_lens(dst_type, src_type)
        inst.next_hdr = next_hdr
        inst.total_len = cls.LEN + inst.addrs_len
        inst.hdr_len = cls.bytes_to_hdr_len(inst.total_len)
        inst._iof_idx = inst._hof_idx = 0
        return inst

    def pack(self):
        packed = []
        types = ((self.version << 12) | (self.dst_addr_type << 6) |
                 self.src_addr_type)
        packed.append(struct.pack("!HHB", types, self.total_len, self.hdr_len))
        curr_iof_p = curr_hof_p = 0
        # FIXME(kormat): NB this assumes that all OFs have the same length.
        if self._iof_idx or self._hof_idx:
            curr_iof_p = self.LEN + self.addrs_len + self._iof_idx * OpaqueField.LEN
        if self._hof_idx:
            curr_hof_p = self.LEN + self.addrs_len + self._hof_idx * OpaqueField.LEN
        packed.append(struct.pack("!BBB", curr_iof_p//LINE_LEN,
                                  curr_hof_p//LINE_LEN, self.next_hdr))
        raw = b"".join(packed)
        assert len(raw) == self.LEN
        return raw

    def validate(self, pkt_len, path_len):
        if pkt_len != self.total_len:
            raise SCMPBadPktLen(
                "Packet length incorrect. Expected: %sB. Actual: %sB" %
                (self.total_len, pkt_len), 0)
        if path_len == 0:
            # Empty path
            if self._iof_idx != 0:
                raise SCMPBadIOFOffset(
                    "Non-zero IOF index for empty path: %s" % self._iof_idx)
            if self._hof_idx != 0:
                raise SCMPBadHOFOffset(
                    "Non-zero HOF index for empty path: %s" % self._hof_idx)
        elif self._hof_idx == 0:
            raise SCMPBadHOFOffset("Zero HOF index for non-empty path")

    def get_of_idxs(self):  # pragma: no cover
        return self._iof_idx, self._hof_idx

    def set_of_idxs(self, iof_idx, hof_idx):  # pragma: no cover
        self._iof_idx = iof_idx
        self._hof_idx = hof_idx

    @classmethod
    def bytes_to_hdr_len(cls, bytes_):
        assert bytes_ % LINE_LEN == 0
        return bytes_ // LINE_LEN

    def hdr_len_bytes(self):  # pragma: no cover
        return self.hdr_len * LINE_LEN

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        values = {
            "dst_addr_type": haddr_get_type(self.dst_addr_type).name(),
            "src_addr_type": haddr_get_type(self.src_addr_type).name(),
            "hdr_len": self.hdr_len_bytes(),
        }
        for i in ("version", "total_len", "_iof_idx", "_hof_idx", "next_hdr"):
            values[i] = getattr(self, i)
        return (
            "CH ver: %(version)s, dst type: %(dst_addr_type)s, src type: %(src_addr_type)s, "
            "total len: %(total_len)sB, hdr len: %(hdr_len)sB, "
            "IOF idx: %(_iof_idx)s, HOF idx: %(_hof_idx)s, "
            "next hdr: %(next_hdr)s" % values)


class SCIONAddrHdr(Serializable):
    """SCION Address header."""
    NAME = "SCIONAddrHdr"
    BLK_SIZE = 8

    def __init__(self, raw_values=()):  # pragma: no cover
        """
        :param tuple raw:
            Tuple of dst addr type, src addr type, and raw addr bytes.
        """
        super().__init__()
        self.dst = None
        self.src = None
        self._pad_len = None
        self._total_len = None
        if raw_values:
            self._parse(*raw_values)

    def _parse(self, dst_type, src_type, raw):
        data = Raw(raw, self.NAME, self.calc_lens(dst_type, src_type)[0])
        dst_ia = ISD_AS(data.pop(ISD_AS.LEN))
        src_ia = ISD_AS(data.pop(ISD_AS.LEN))
        dst_addr_t = haddr_get_type(dst_type)
        dst_addr = dst_addr_t(data.pop(dst_addr_t.LEN))
        self.dst = SCIONAddr.from_values(dst_ia, dst_addr)
        src_addr_t = haddr_get_type(src_type)
        src_addr = src_addr_t(data.pop(src_addr_t.LEN))
        self.src = SCIONAddr.from_values(src_ia, src_addr)
        self.update()
        if self.src.host.TYPE == AddrType.SVC:
            raise SCMPBadSrcType("Invalid source type: SVC")

    @classmethod
    def from_values(cls, dst, src):  # pragma: no cover
        """
        dst/src must be a :any:`SCIONAddr`
        """
        inst = cls()
        inst.dst = dst
        inst.src = src
        inst.update()
        return inst

    def pack(self):
        self.update()
        packed = []
        packed.append(self.dst.isd_as.pack())
        packed.append(self.src.isd_as.pack())
        packed.append(self.dst.host.pack())
        packed.append(self.src.host.pack())
        packed.append(bytes(self._pad_len))
        raw = b"".join(packed)
        assert len(raw) % self.BLK_SIZE == 0
        assert len(raw) == self._total_len
        return raw

    def validate(self):  # pragma: no cover
        if self.dst.host.TYPE == AddrType.SVC:
            if self.dst.host.anycast() not in [SVCType.BS_A, SVCType.PS_A,
                                               SVCType.CS_A, SVCType.SB_A]:
                raise SCMPBadHost("Invalid dest SVC: %s" % self.dst.host.addr)
        if self.src.host.TYPE == AddrType.SVC:
            raise SCMPBadSrcType("Invalid source type: SVC")

    def update(self):
        self._total_len, self._pad_len = self.calc_lens(
            self.dst.host.TYPE, self.src.host.TYPE)

    @classmethod
    def calc_lens(cls, dst_type, src_type):
        try:
            data_len = SCIONAddr.calc_len(dst_type)
        except HostAddrInvalidType:
            raise SCMPBadDstType(
                "Unsupported dst address type: %s" % dst_type) from None
        try:
            data_len += SCIONAddr.calc_len(src_type)
        except HostAddrInvalidType:
            raise SCMPBadSrcType(
                "Unsupported src address type: %s" % src_type) from None
        pad_len = calc_padding(data_len, cls.BLK_SIZE)
        total_len = data_len + pad_len
        assert total_len % cls.BLK_SIZE == 0
        return total_len, pad_len

    def reverse(self):
        self.dst, self.src = self.src, self.dst
        self.update()

    def dst_type(self):  # pragma: no cover
        return self.dst.host.TYPE

    def src_type(self):  # pragma: no cover
        return self.src.host.TYPE

    def __len__(self):  # pragma: no cover
        assert self._total_len is not None
        return self._total_len

    def __str__(self):
        return "%s(%sB): Dst:<%s> Src:<%s>" % (self.NAME, len(self), self.dst, self.src)


class SCIONBasePacket(PacketBase):
    """
    Encasulates the basic headers (common header, address header, and path
    header). Everything else is stored as payload.
    """
    NAME = "SCIONBasePacket"
    MIN_LEN = SCIONCommonHdr.LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.cmn_hdr = None
        self.addrs = None
        self.path = None
        self._l4_proto = L4Proto.NONE
        self._payload = b""
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self._inner_parse(data)
        self.set_payload(PayloadRaw(data.get()))

    def _inner_parse(self, data):  # pragma: no cover
        self.cmn_hdr = SCIONCommonHdr(data.pop(SCIONCommonHdr.LEN))
        self._parse_addrs(data)
        self._parse_path(data)

    def _parse_addrs(self, data):
        self.addrs = SCIONAddrHdr((
            self.cmn_hdr.dst_addr_type,
            self.cmn_hdr.src_addr_type,
            data.get(self.cmn_hdr.addrs_len),
        ))
        data.pop(len(self.addrs))

    def _parse_path(self, data):
        count = self.cmn_hdr.hdr_len_bytes() - data.offset()
        if count < 0:
            raise SCIONParseError(
                "Bad header len field (%sB), implies negative path length" %
                self.cmn_hdr.hdr_len_bytes(),
            )
        if count > len(data):
            raise SCIONParseError(
                "Bad header len field (%sB), "
                "implies path is longer than packet (%sB)"
                % (self.cmn_hdr.hdr_len_bytes(), len(data) + data.offset())
            )
        self.path = parse_path(data.get(count))
        data.pop(len(self.path))
        iof_idx, hof_idx = self.cmn_hdr.get_of_idxs()
        self.path.set_of_idxs(iof_idx, hof_idx)

    @classmethod
    def from_values(cls, cmn_hdr, addr_hdr, path_hdr, payload=None):
        inst = cls()
        inst._inner_from_values(cmn_hdr, addr_hdr, path_hdr)
        if payload is None:
            payload = PayloadRaw()
        inst.set_payload(payload)
        inst.update()
        return inst

    def _inner_from_values(self, cmn_hdr, addr_hdr, path_hdr):
        assert isinstance(cmn_hdr, SCIONCommonHdr), type(cmn_hdr)
        self.cmn_hdr = cmn_hdr
        assert isinstance(addr_hdr, SCIONAddrHdr), type(addr_hdr)
        self.addrs = addr_hdr
        assert isinstance(path_hdr, SCIONPath), type(path_hdr)
        self.path = path_hdr

    def get_fwd_ifid(self):
        """
        Returns the next forwarding interface ID of the path or 0 if the path is
        empty.
        """
        if self.path:
            return self.path.get_fwd_if()
        return 0

    def pack(self):
        self.update()
        packed = []
        inner = self._inner_pack()
        self.cmn_hdr.total_len = self.cmn_hdr.hdr_len_bytes() + len(inner)
        packed.append(self.cmn_hdr.pack())
        packed.append(self.addrs.pack())
        packed.append(self.path.pack())
        packed.append(inner)
        raw = b"".join(packed)
        assert len(raw) == self.cmn_hdr.total_len
        return raw

    def _inner_pack(self):  # pragma: no cover
        return b""

    def _pack_payload(self):  # pragma: no cover
        return self._payload.pack()

    def validate(self, pkt_len):
        """Called after parsing, to check for errors that don't break parsing"""
        path_len = len(self.path)
        self.cmn_hdr.validate(pkt_len, path_len)
        self.addrs.validate()
        if path_len:
            self._validate_of_idxes()
        assert isinstance(self._payload, PayloadRaw), type(self._payload)

    def _validate_of_idxes(self):
        try:
            self.path.get_iof()
        except SCIONIndexError as e:
            raise SCMPBadIOFOffset("%s" % e) from None
        try:
            self.path.get_hof()
        except SCIONIndexError as e:
            raise SCMPBadHOFOffset("%s" % e) from None

    def update(self):
        self.addrs.update()
        self._update_cmn_hdr()

    def _update_cmn_hdr(self):
        hdr = self.cmn_hdr
        hdr.dst_addr_type = self.addrs.dst_type()
        hdr.src_addr_type = self.addrs.src_type()
        hdr.addrs_len = len(self.addrs)
        hdr.hdr_len = hdr.bytes_to_hdr_len(len(hdr) + len(self.addrs) + len(self.path))
        hdr.total_len = hdr.hdr_len_bytes() + self._get_offset_len()
        hdr.set_of_idxs(*self.path.get_of_idxs())
        hdr.next_hdr = self._get_next_hdr()

    def _get_offset_len(self):  # pragma: no cover
        return 0

    def _get_next_hdr(self):  # pragma: no cover
        return self._l4_proto

    def reverse(self):
        self.addrs.reverse()
        self.path.reverse()

    def reversed_copy(self):  # pragma: no cover
        inst = copy.deepcopy(self)
        inst.reverse()
        return inst

    def convert_to_scmp_error(self, addr, class_, type_, pkt, *args,
                              hopbyhop=False, **kwargs):
        self.addrs.src = addr
        if self.ext_hdrs:
            if self.ext_hdrs[0].EXT_TYPE == ExtHopByHopType.SCMP:
                # Remove any existing SCMP ext header
                del self.ext_hdrs[0]
        # Insert SCMP ext at start of headers
        self.ext_hdrs.insert(0, SCMPExt.from_values(hopbyhop=hopbyhop))
        # Trim any extra headers, in the case of SCMPTooManyHopByHop, max+1 as
        # the SCMP ext header isn't counted.
        self.ext_hdrs = self.ext_hdrs[:MAX_HOPBYHOP_EXT + 1]
        # Create SCMP payload.
        pld = SCMPPayload.from_pkt(class_, type_, pkt, *args, **kwargs)
        self.l4_hdr = SCMPHeader.from_values(self.addrs.src, self.addrs.dst,
                                             class_, type_)
        self.set_payload(pld)

    def short_desc(self):
        s = []
        s.append("%s(%dB):" % (self.NAME, len(self)))
        s.append("  %s" % self.cmn_hdr)
        s.append("  %s" % self.addrs)
        s.extend(self._inner_str())
        return "\n".join(s)

    def __len__(self):  # pragma: no cover
        return self.cmn_hdr.total_len

    def __str__(self):
        s = []
        s.append("%s(%dB):" % (self.NAME, len(self)))
        s.append("  %s" % self.cmn_hdr)
        s.append("  %s" % self.addrs)
        for line in str(self.path).splitlines():
            s.append("  %s" % line)
        s.extend(self._inner_str())
        s.append("  Payload:")
        for line in str(self._payload).splitlines():
            s.append("    %s" % line)
        return "\n".join(s)

    def _inner_str(self):  # pragma: no cover
        return []


class SCIONExtPacket(SCIONBasePacket):
    """
    Extends :any:`SCIONBasePacket` to handle extension headers.
    """
    NAME = "SCIONExtPacket"

    def __init__(self, raw=None):  # pragma: no cover
        self.ext_hdrs = []
        self._unknown_exts = {}
        super().__init__(raw)

    def _inner_parse(self, data):  # pragma: no cover
        super()._inner_parse(data)
        # Parse extension headers
        self.ext_hdrs, self._l4_proto, self._unknown_exts = parse_extensions(
            data, self.cmn_hdr.next_hdr)

    @classmethod
    def from_values(cls, cmn_hdr, addr_hdr, path_hdr, ext_hdrs, payload=b""):
        inst = cls()
        inst._inner_from_values(cmn_hdr, addr_hdr, path_hdr, ext_hdrs)
        inst.set_payload(payload)
        return inst

    def _inner_from_values(self, cmn_hdr, addr_hdr, path_hdr, ext_hdrs):
        super()._inner_from_values(cmn_hdr, addr_hdr, path_hdr)
        for hdr in ext_hdrs:
            assert isinstance(hdr, ExtensionHeader), type(hdr)
            self.ext_hdrs.append(hdr)

    def get_fwd_ifid(self):
        """
        Returns the next forwarding interface ID depending on the extension
        headers and the path in the packet.
        """
        for hdr in self.ext_hdrs:
            if_id = hdr.get_next_ifid()
            if if_id is not None:
                return if_id
        return super().get_fwd_ifid()

    def pack_exts(self):
        packed = []
        max_idx = len(self.ext_hdrs) - 1
        for i, hdr in enumerate(self.ext_hdrs):
            ext_packed = []
            next_hdr = self._l4_proto
            if i < max_idx:
                next_hdr = self.ext_hdrs[i+1].EXT_CLASS
            ext_packed.append(struct.pack("!BBB", next_hdr, hdr.hdr_len(),
                                          hdr.EXT_TYPE))
            ext_packed.append(hdr.pack())
            ext = b"".join(ext_packed)
            assert len(ext) % ExtensionHeader.LINE_LEN == 0
            packed.append(ext)
        return b"".join(packed)

    def _inner_pack(self):
        return super()._inner_pack() + self.pack_exts()

    def _get_offset_len(self):
        l = super()._get_offset_len()
        for hdr in self.ext_hdrs:
            l += len(hdr)
        return l

    def _get_next_hdr(self):
        if self.ext_hdrs:
            return self.ext_hdrs[0].EXT_CLASS
        else:
            return self._l4_proto

    def validate(self, pkt_len):
        super().validate(pkt_len)
        if not self._unknown_exts:
            return True
        # Use the first unknown extension, and use that for the SCMP error
        # message.
        hbh = self._unknown_exts.get(ExtensionClass.HOP_BY_HOP)
        if hbh:
            raise SCMPBadHopByHop(hbh[0])
        e2e = self._unknown_exts.get(ExtensionClass.END_TO_END)
        if e2e:
            raise SCMPBadEnd2End(e2e[0])

    def _inner_str(self):  # pragma: no cover
        s = super()._inner_str()
        for hdr in self.ext_hdrs:
            for line in str(hdr).splitlines():
                s.append("  %s" % line)
        return s

    def reverse(self):  # pragma: no cover
        for hdr in self.ext_hdrs:
            hdr.reverse()
        super().reverse()


class SCIONL4Packet(SCIONExtPacket):
    """
    Extends :any:`SCIONExtPacket` to handle L4 headers.
    """
    NAME = "SCIONL4Packet"

    def __init__(self, raw=None):  # pragma: no cover
        self.l4_hdr = None
        super().__init__(raw)

    def _inner_parse(self, data):
        super()._inner_parse(data)
        # Parse L4 header
        self.l4_hdr = parse_l4_hdr(
            self._l4_proto, data, dst=self.addrs.dst, src=self.addrs.src)

    @classmethod
    def from_values(cls, cmn_hdr, addr_hdr, path_hdr, ext_hdrs, l4_hdr,
                    payload=None):
        inst = cls()
        inst._inner_from_values(cmn_hdr, addr_hdr, path_hdr, ext_hdrs, l4_hdr)
        if payload is None:
            payload = PayloadRaw()
        inst.set_payload(payload)
        inst.update()
        return inst

    def _inner_from_values(self, cmn_hdr, addr_hdr, path_hdr, ext_hdrs, l4_hdr):
        super()._inner_from_values(cmn_hdr, addr_hdr, path_hdr, ext_hdrs)
        assert isinstance(l4_hdr, L4HeaderBase), type(l4_hdr)
        self.l4_hdr = l4_hdr
        self._l4_proto = l4_hdr.TYPE

    def _inner_pack(self):
        self.update()
        packed = [super()._inner_pack()]
        pld = super()._pack_payload()
        if self.l4_hdr:
            packed.append(self.l4_hdr.pack(pld))
        packed.append(pld)
        return b"".join(packed)

    def _pack_payload(self):  # pragma: no cover
        # Payload is already packed and included as part of _inner_pack
        return b""

    def validate(self, pkt_len):  # pragma: no cover
        super().validate(pkt_len)
        if self.l4_hdr:
            self.l4_hdr.validate(self._payload.pack())

    def update(self):
        if self.l4_hdr:
            self.l4_hdr.update(src=self.addrs.src, dst=self.addrs.dst)
            self._l4_proto = self.l4_hdr.TYPE
        super().update()

    def reverse(self):  # pragma: no cover
        if self.l4_hdr:
            self.l4_hdr.reverse()
        super().reverse()

    def parse_payload(self):
        if not self.l4_hdr:
            raise SCIONParseError("Cannot parse payload of non-L4 packet")
        praw = self._payload.pack()
        if self.l4_hdr.TYPE == L4Proto.UDP:
            # Treat as SCION control message
            pld = CtrlPayload.from_raw(praw)
        elif self.l4_hdr.TYPE == L4Proto.SCMP:
            pld = SCMPPayload((self.l4_hdr.class_, self.l4_hdr.type, praw))
        self.set_payload(pld)
        return pld

    def _get_offset_len(self):
        l = super()._get_offset_len()
        if self.l4_hdr:
            l += self.l4_hdr.total_len
        return l

    def _inner_str(self):  # pragma: no cover
        s = super()._inner_str()
        s.append("  %s" % self.l4_hdr)
        return s

    def get_l4_proto(self):  # pragma: no cover
        return self._l4_proto


def build_base_hdrs(dst, src, l4=L4Proto.UDP):
    cmn_hdr = SCIONCommonHdr.from_values(dst.host.TYPE, src.host.TYPE, l4)
    addr_hdr = SCIONAddrHdr.from_values(dst, src)
    return cmn_hdr, addr_hdr
