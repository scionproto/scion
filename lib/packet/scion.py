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
from lib.defines import L4_DEFAULT, L4_NONE
from lib.errors import SCIONParseError
from lib.packet.cert_mgmt import parse_certmgmt_payload
from lib.packet.ext_hdr import ExtensionHeader
from lib.packet.ext_util import parse_extensions
from lib.packet.host_addr import HostAddrSVC, haddr_get_type
from lib.packet.opaque_field import OpaqueField
from lib.packet.packet_base import (
    HeaderBase,
    L4HeaderBase,
    PacketBase,
    PayloadRaw,
    SCIONPayloadBase,
)
from lib.packet.path import PathBase, parse_path
from lib.packet.path_mgmt import parse_pathmgmt_payload
from lib.packet.pcb import parse_pcb_payload
from lib.packet.scion_addr import ISD_AD, SCIONAddr
from lib.packet.scion_l4 import parse_l4_hdr
from lib.sibra.payload import parse_sibra_payload
from lib.types import PayloadClass, IFIDType
from lib.util import Raw, calc_padding


class PacketType(object):
    """
    Defines constants for the SCION packet types.
    """
    # Data packet
    DATA = HostAddrSVC(0, raw=False)
    # Path Construction Beacon
    BEACON = HostAddrSVC(1, raw=False)
    # Path management packet from/to PS
    PATH_MGMT = HostAddrSVC(2, raw=False)
    # TRC file request to parent AD
    CERT_MGMT = HostAddrSVC(3, raw=False)
    # IF ID packet to the peer router
    IFID_PKT = HostAddrSVC(4, raw=False)
    # SIBRA service
    SB_PKT = HostAddrSVC(5, raw=False)


class SCIONCommonHdr(HeaderBase):
    """
    Encapsulates the common header for SCION packets.
    """
    LEN = 8

    def __init__(self, raw=None):
        """
        Initialize an instance of the class SCIONCommonHdr.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.version = 0  # Version of SCION packet.
        self.src_addr_type = None  # Type of the src address.
        self.dst_addr_type = None  # Length of the dst address.
        self.addrs_len = None  # Length of the address block
        self.total_len = None  # Total length of the packet.
        self._iof_idx = None  # Index of the current Info Opaque Field
        self._hof_idx = None  # Index of the current Hop Opaque Field
        self.next_hdr = None  # Type of the next hdr field (IP protocol numbers)
        self.hdr_len = None  # Header length including the path.

        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Parses the raw data and populates the fields accordingly.
        """
        self._raw = raw
        data = Raw(raw, "SCIONCommonHdr", self.LEN)
        (types, self.total_len, curr_iof_p, curr_hof_p,
         self.next_hdr, self.hdr_len) = struct.unpack("!HHBBBB", data.pop())
        self.version = (types & 0xf000) >> 12
        self.src_addr_type = (types & 0x0fc0) >> 6
        self.dst_addr_type = types & 0x003f
        self.addrs_len = SCIONAddrHdr.calc_len(self.src_addr_type,
                                               self.dst_addr_type)
        first_of_offset = self.LEN + self.addrs_len
        # FIXME(kormat): NB this assumes that all OFs have the same length.
        self._iof_idx = (curr_iof_p - first_of_offset) // OpaqueField.LEN
        self._hof_idx = (curr_hof_p - first_of_offset) // OpaqueField.LEN

    @classmethod
    def from_values(cls, src_type, dst_type, next_hdr=L4_NONE):
        """
        Returns a SCIONCommonHdr object with the values specified.

        :param int src: Source address type.
        :param int dst: Destination address type.
        :param int next_hdr: Next header type.
        """
        inst = cls()
        inst.src_addr_type = src_type
        inst.dst_addr_type = dst_type
        inst.addrs_len = SCIONAddrHdr.calc_len(src_type, dst_type)
        inst.next_hdr = next_hdr or L4_DEFAULT
        inst.total_len = inst.hdr_len = cls.LEN + inst.addrs_len
        inst._iof_idx = inst._hof_idx = 0
        return inst

    def pack(self):
        packed = []
        types = ((self.version << 12) | (self.src_addr_type << 6) |
                 self.dst_addr_type)
        packed.append(struct.pack("!HH", types, self.total_len))
        curr_iof_p = curr_hof_p = self.LEN + self.addrs_len
        if self._iof_idx:
            curr_iof_p += self._iof_idx * OpaqueField.LEN
        if self._hof_idx:
            curr_hof_p += self._hof_idx * OpaqueField.LEN
        packed.append(struct.pack("!BB", curr_iof_p, curr_hof_p))
        packed.append(struct.pack("!BB", self.next_hdr, self.hdr_len))
        raw = b"".join(packed)
        assert len(raw) == self.LEN
        return raw

    def get_of_idxs(self):
        return self._iof_idx, self._hof_idx

    def set_of_idxs(self, iof_idx, hof_idx):
        self._iof_idx = iof_idx
        self._hof_idx = hof_idx

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        values = {
            "src_addr_type": haddr_get_type(self.src_addr_type).name(),
            "dst_addr_type": haddr_get_type(self.dst_addr_type).name(),
        }
        for i in ("version", "total_len",
                  "_iof_idx", "_hof_idx", "next_hdr", "hdr_len"):
            values[i] = getattr(self, i)
        return (
            "[CH ver: %(version)d, src type: %(src_addr_type)s, "
            "dst type: %(dst_addr_type)s, total len: %(total_len)dB, "
            "IOF idx: %(_iof_idx)d, HOF idx: %(_hof_idx)d, "
            "next hdr: %(next_hdr)d, hdr len: %(hdr_len)dB]" % values)


class SCIONAddrHdr(HeaderBase):
    """
    SCION Address header.
    """
    BLK_SIZE = 8

    def __init__(self, raw_values=()):
        """
        :param tuple raw:
            Tuple of src addr type, dst addr type, and raw addr bytes.
        """
        super().__init__()
        self.src_isd = None
        self.src_ad = None
        self.src_addr = None
        self.dst_isd = None
        self.dst_ad = None
        self.dst_addr = None
        self._pad_len = None
        self._total_len = None
        if raw_values:
            self._parse(*raw_values)

    def _parse(self, src_type, dst_type, raw):
        # FIXME(kormat): how to handle `None` addr type?
        data = Raw(raw, "SCIONAddrHdr", self.calc_len(src_type, dst_type))
        src_class = haddr_get_type(src_type)
        dst_class = haddr_get_type(dst_type)
        self.src_isd, self.src_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.src_addr = src_class(data.pop(src_class.LEN))
        self.dst_isd, self.dst_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.dst_addr = dst_class(data.pop(dst_class.LEN))
        self.update()

    @classmethod
    def from_values(cls, src, dst):
        """
        src_addr/dst_addr must be a :any:`SCIONAddr`
        """
        inst = cls()
        inst.src_isd = src.isd_id
        inst.src_ad = src.ad_id
        inst.src_addr = src.host_addr
        inst.dst_isd = dst.isd_id
        inst.dst_ad = dst.ad_id
        inst.dst_addr = dst.host_addr
        inst.update()
        return inst

    def pack(self):
        self.update()
        packed = []
        packed.append(ISD_AD(self.src_isd, self.src_ad).pack())
        packed.append(self.src_addr.pack())
        packed.append(ISD_AD(self.dst_isd, self.dst_ad).pack())
        packed.append(self.dst_addr.pack())
        packed.append(bytes(self._pad_len))
        raw = b"".join(packed)
        assert len(raw) % self.BLK_SIZE == 0
        assert len(raw) == self._total_len
        return raw

    def update(self):
        self._total_len, self._pad_len = self.calc_len(
            self.src_addr.TYPE, self.dst_addr.TYPE, both=True)

    @classmethod
    def calc_len(cls, src_type, dst_type, both=False):
        src_class = haddr_get_type(src_type)
        dst_class = haddr_get_type(dst_type)
        data_len = ISD_AD.LEN * 2 + src_class.LEN + dst_class.LEN
        pad_len = calc_padding(data_len, cls.BLK_SIZE)
        total_len = data_len + pad_len
        assert total_len % cls.BLK_SIZE == 0
        if both:
            return total_len, pad_len
        else:
            return total_len

    def reverse(self):
        self.src_isd, self.dst_isd = self.dst_isd, self.src_isd
        self.src_ad, self.dst_ad = self.dst_ad, self.src_ad
        self.src_addr, self.dst_addr = self.dst_addr, self.src_addr
        self.update()

    def get_src_addr(self):  # pragma: no cover
        return SCIONAddr.from_values(self.src_isd, self.src_ad, self.src_addr)

    def get_dst_addr(self):  # pragma: no cover
        return SCIONAddr.from_values(self.dst_isd, self.dst_ad, self.dst_addr)

    def __len__(self):
        assert self._total_len is not None
        return self._total_len

    def __str__(self):
        s = []
        s.append("SCIONAddrHdr(%dB):" % len(self))
        s.append("Src<isd:%d ad:%d host(%s):%s>" % (
            self.src_isd, self.src_ad, self.src_addr.name(), self.src_addr))
        s.append("Dst<isd:%d ad:%d host(%s):%s>" % (
            self.dst_isd, self.dst_ad, self.dst_addr.name(), self.dst_addr))
        return " ".join(s)


class SCIONBasePacket(PacketBase):
    """
    Encasulates the basic headers (common header, address header, and path
    header). Everything else is stored as payload.
    """
    MIN_LEN = SCIONCommonHdr.LEN
    NAME = "SCIONBasePacket"

    def __init__(self, raw=None):
        super().__init__()
        self.cmn_hdr = None
        self.addrs = None
        self.path = None
        self._l4_proto = L4_NONE
        self._payload = b""
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self._inner_parse(data)
        payload = PayloadRaw(data.get())
        self.set_payload(payload)

    def _inner_parse(self, data):
        self._parse_cmn_hdr(data)
        self._parse_addrs(data)
        self._parse_path(data, self.cmn_hdr.hdr_len - data.offset())

    def _parse_cmn_hdr(self, data):
        total_len = len(data)
        self.cmn_hdr = SCIONCommonHdr(data.pop(SCIONCommonHdr.LEN))
        if total_len != self.cmn_hdr.total_len:
            raise SCIONParseError(
                "Packet length incorrect. Expected: %dB. Actual: %dB\n%s" %
                (self.cmn_hdr.total_len, total_len, self.cmn_hdr))

    def _parse_addrs(self, data):
        self.addrs = SCIONAddrHdr((
            self.cmn_hdr.src_addr_type,
            self.cmn_hdr.dst_addr_type,
            data.get(self.cmn_hdr.addrs_len),
        ))
        data.pop(len(self.addrs))

    def _parse_path(self, data, count):
        self.path = parse_path(data.get(count))
        data.pop(len(self.path))
        self.path.set_of_idxs(*self.cmn_hdr.get_of_idxs())

    @classmethod
    def from_values(cls, cmn_hdr, addr_hdr, path_hdr, payload=b""):
        inst = cls()
        inst._inner_from_values(cmn_hdr, addr_hdr, path_hdr)
        inst.set_payload(PayloadRaw(payload))
        inst.update()
        return inst

    def _inner_from_values(self, cmn_hdr, addr_hdr, path_hdr):
        assert isinstance(cmn_hdr, SCIONCommonHdr)
        self.cmn_hdr = cmn_hdr
        assert isinstance(addr_hdr, SCIONAddrHdr)
        self.addrs = addr_hdr
        assert isinstance(path_hdr, PathBase)
        self.path = path_hdr

    def pack(self):
        self.update()
        packed = []
        packed.append(self.cmn_hdr.pack())
        packed.append(self.addrs.pack())
        packed.append(self.path.pack())
        packed.append(self._inner_pack())
        packed.append(self._pack_payload())
        raw = b"".join(packed)
        assert len(raw) == self.cmn_hdr.total_len
        return raw

    def _inner_pack(self):  # pragma: no cover
        return b""

    def _pack_payload(self):  # pragma: no cover
        return self._payload.pack_full()

    def update(self):
        self.addrs.update()
        self._update_cmn_hdr()

    def _update_cmn_hdr(self):
        hdr = self.cmn_hdr
        hdr.src_addr_type = self.addrs.src_addr.TYPE
        hdr.dst_addr_type = self.addrs.dst_addr.TYPE
        hdr.addrs_len = len(self.addrs)
        hdr.hdr_len = len(hdr) + len(self.addrs) + len(self.path)
        hdr.total_len = hdr.hdr_len + self._get_offset_len()
        hdr.set_of_idxs(*self.path.get_of_idxs())
        hdr.next_hdr = self._get_next_hdr()

    def _get_offset_len(self):  # pragma: no cover
        return self._payload.total_len()

    def _get_next_hdr(self):  # pragma: no cover
        return self._l4_proto

    def reverse(self):
        self.addrs.reverse()
        self.path.reverse()

    def reversed_copy(self):  # pragma: no cover
        inst = copy.deepcopy(self)
        inst.reverse()
        return inst

    def __len__(self):
        return len(self.cmn_hdr) + len(self.addrs) + \
            len(self.path) + self._get_offset_len()

    def __str__(self):
        s = []
        s.append("%s(%dB):" % (self.NAME, len(self)))
        s.append("  %s" % self.cmn_hdr)
        s.append("  %s" % self.addrs)
        for line in str(self.path).splitlines():
            s.append("  %s" % line)
        s.extend(self._inner_str())
        s.append("  Payload(%dB): %s" % (
            len(self._payload), self._payload))
        return "\n".join(s)

    def _inner_str(self):  # pragma: no cover
        return []


class SCIONExtPacket(SCIONBasePacket):
    """
    Extends :any:`SCIONBasePacket` to handle extension headers.
    """
    NAME = "SCIONExtPacket"

    def __init__(self, raw=None):
        super().__init__()
        self.ext_hdrs = []
        if raw is not None:
            self._parse(raw)

    def _inner_parse(self, data):
        super()._inner_parse(data)
        # Parse extension headers
        self.ext_hdrs, self._l4_proto = parse_extensions(
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
            assert isinstance(hdr, ExtensionHeader)
            self.ext_hdrs.append(hdr)

    def _inner_pack(self):
        packed = [super()._inner_pack()]
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

    def __init__(self, raw=None):
        super().__init__()
        self.l4_hdr = None
        if raw is not None:
            self._parse(raw)

    def _inner_parse(self, data):
        super()._inner_parse(data)
        # Parse L4 header
        self.l4_hdr = parse_l4_hdr(
            self._l4_proto, data,
            src_addr=self.addrs.get_src_addr(),
            dst_addr=self.addrs.get_dst_addr())

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
        assert isinstance(l4_hdr, L4HeaderBase)
        self.l4_hdr = l4_hdr
        self._l4_proto = l4_hdr.TYPE

    def _inner_pack(self):
        self.update()
        packed = [super()._inner_pack()]
        if self.l4_hdr:
            packed.append(self.l4_hdr.pack())
        return b"".join(packed)

    def update(self):
        if self.l4_hdr:
            self.l4_hdr.update(
                src_addr=self.addrs.get_src_addr(),
                dst_addr=self.addrs.get_dst_addr(), payload=self._payload)
            self._l4_proto = self.l4_hdr.TYPE
        super().update()

    def reverse(self):  # pragma: no cover
        if self.l4_hdr:
            self.l4_hdr.reverse()
        super().reverse()

    def parse_payload(self):
        data = Raw(self._payload.pack(), "SCIONL4Packet.parse_payload")
        pld_class = data.pop(1)
        class_map = {
            PayloadClass.PCB: parse_pcb_payload,
            PayloadClass.IFID: parse_ifid_payload,
            PayloadClass.CERT: parse_certmgmt_payload,
            PayloadClass.PATH: parse_pathmgmt_payload,
            PayloadClass.SIBRA: parse_sibra_payload,
        }
        handler = class_map.get(pld_class)
        if not handler:
            raise SCIONParseError("Unsupported payload class: %s" % pld_class)
        pld = handler(data.pop(1), data)
        self.set_payload(pld)
        return pld

    def _get_offset_len(self):
        l = super()._get_offset_len()
        if self.l4_hdr:
            l += len(self.l4_hdr)
        return l

    def _inner_str(self):  # pragma: no cover
        s = super()._inner_str()
        s.append("  %s" % self.l4_hdr)
        return s


class IFIDPayload(SCIONPayloadBase):
    """
    IFID packet.
    """
    PAYLOAD_CLASS = PayloadClass.IFID
    PAYLOAD_TYPE = IFIDType.PAYLOAD
    NAME = "IFIDPayload"
    LEN = 4

    def __init__(self, raw=None):
        """
        Initialize an instance of the class IFIDPacket.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.reply_id = 0  # Always 0 for initial request.
        self.request_id = None
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.reply_id, self.request_id = struct.unpack(
            "!HH", data.pop(self.LEN))

    @classmethod
    def from_values(cls, request_id):
        inst = cls()
        inst.request_id = request_id
        return inst

    def pack(self):
        return struct.pack("!HH", self.reply_id, self.request_id)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return "[IFID (%dB): reply ID:%d request ID:%d]" % (
            self.LEN, self.reply_id, self.request_id)


def build_base_hdrs(src, dst):
    cmn_hdr = SCIONCommonHdr.from_values(src.host_addr.TYPE, dst.host_addr.TYPE)
    addr_hdr = SCIONAddrHdr.from_values(src, dst)
    return cmn_hdr, addr_hdr


def parse_ifid_payload(type_, data):
    type_map = {
        IFIDType.PAYLOAD: (IFIDPayload, IFIDPayload.LEN)
    }
    if type_ not in type_map:
        raise SCIONParseError("Unsupported IFID type: %s", type_)
    handler, len_ = type_map[type_]
    return handler(data.pop(len_))
