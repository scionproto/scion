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
:mod:`info` --- SCMP info
=========================
"""
# Stdlib
import os
import struct
from abc import ABCMeta, abstractmethod

# SCION
from lib.defines import LINE_LEN
from lib.packet.opaque_field import OpaqueField
from lib.packet.packet_base import Serializable
from lib.packet.scmp.types import SCMPInfoType
from lib.packet.scmp.util import scmp_get_info_type
from lib.util import Raw, calc_padding, hex_str


class SCMPInfo(Serializable, metaclass=ABCMeta):
    @classmethod
    def from_values(cls, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def from_pkt(self, *args, **kwargs):
        raise NotImplementedError

    @abstractmethod
    def __str__(self):
        raise NotImplementedError


class SCMPInfoString(SCMPInfo):
    """Store a single string."""
    NAME = "SCMPInfoString"
    VLEN_LEN = 2

    def __init__(self, raw=None):
        self.val = ""
        super().__init__(raw)

    def _parse(self, raw):
        vlen = struct.unpack("!H", raw[:self.VLEN_LEN])[0]
        data = Raw(raw, self.NAME, self._calc_len(vlen))
        fmt = self._calc_fmt(vlen)
        _, self.val = struct.unpack(fmt, data.pop())

    @classmethod
    def from_pkt(cls, _, str_):  # pragma: no cover
        inst = cls()
        inst.val = str_.encode("utf8")
        return inst

    def pack(self):
        vlen = len(self.val)
        fmt = self._calc_fmt(vlen)
        return struct.pack(fmt, vlen, self.val)

    def _calc_len(self, vlen):  # pragma: no cover
        l = self.VLEN_LEN + vlen
        l += calc_padding(l, LINE_LEN)
        return l

    def _calc_fmt(self, vlen):
        return "!H%ss%sx" % (vlen, calc_padding(self.VLEN_LEN + vlen, LINE_LEN))

    def __len__(self):  # pragma: no cover
        return self._calc_len(len(self.val))

    def __str__(self):
        return "%s(%dB): value(%dB): \"%s\"" % (
            self.NAME, len(self), len(self.val), self.val.decode("utf8"))


class SCMPInfoGeneric(SCMPInfo):
    """Generic info class."""
    NAME = None
    STRUCT_FMT = ""
    LEN = None
    ATTRIBS = []

    def __init__(self, raw=None):
        self._set_vals([None] * len(self.ATTRIBS))
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, len_=self.LEN)
        self._set_vals(struct.unpack(self.STRUCT_FMT, data.pop()))

    def pack(self):
        return struct.pack(self.STRUCT_FMT, *self._get_vals())

    def _set_vals(self, vals):
        assert len(self.ATTRIBS) == len(vals)
        for name, val in zip(self.ATTRIBS, vals):
            setattr(self, name, val)

    def _get_vals(self):  # pragma: no cover
        vals = []
        for name in self.ATTRIBS:
            vals.append(getattr(self, name))
        return vals

    def __len__(self):  # pragma: no cover
        return self.LEN


class SCMPInfoEcho(SCMPInfoGeneric):
    """Store echo request/reply ID and sequence."""
    NAME = "SCMPInfoEcho"
    STRUCT_FMT = "!2sH4x"
    LEN = struct.calcsize(STRUCT_FMT)
    ATTRIBS = ["id", "seq"]

    @classmethod
    def from_values(cls, id_=None, seq=0):  # pragma: no cover
        inst = cls()
        if id_ is None:
            id_ = os.urandom(2)
        assert isinstance(id_, bytes), type(id_)
        inst._set_vals((id_, seq))
        return inst

    @classmethod
    def from_pkt(cls, pkt):
        raise NotImplementedError

    def __str__(self):
        return "%s(%dB): id:%s seq:%s" % (
            self.NAME, self.LEN, hex_str(self.id), self.seq)


class SCMPInfoPktSize(SCMPInfoGeneric):
    """Store packet size and MTU."""
    NAME = "SCMPInfoPktSize"
    STRUCT_FMT = "!HH4x"
    LEN = struct.calcsize(STRUCT_FMT)
    ATTRIBS = ["pkt_size", "mtu"]

    @classmethod
    def from_pkt(cls, pkt, mtu):  # pragma: no cover
        inst = cls()
        inst._set_vals((len(pkt), mtu))
        return inst

    def __str__(self):
        return "%s(%dB): pkt size: %sB MTU: %sB" % (
            self.NAME, self.LEN, self.pkt_size, self.mtu)


class SCMPInfoPathOffsets(SCMPInfoGeneric):
    """Store IOF offset, HOF offset, IF id and ingress flag."""
    NAME = "SCMPInfoPathOffsets"
    STRUCT_FMT = "!HHH?x"
    LEN = struct.calcsize(STRUCT_FMT)
    ATTRIBS = ["iof_off", "hof_off", "if_id", "ingress"]

    @classmethod
    def from_pkt(cls, pkt, if_id=0, ingress=False):
        inst = cls()
        iof_offset, hof_offset = inst._calc_offsets(pkt)
        inst._set_vals((iof_offset, hof_offset, if_id, ingress))
        return inst

    def _calc_offsets(self, pkt):
        iof_idx, hof_idx = pkt.cmn_hdr.get_of_idxs()
        base_offset = len(pkt.cmn_hdr) + len(pkt.addrs)
        iof_offset = base_offset + iof_idx * OpaqueField.LEN
        hof_offset = base_offset + hof_idx * OpaqueField.LEN
        return iof_offset, hof_offset

    def __str__(self):
        return ("%s(%dB): IOF offset: %sB HOF offset: %sB "
                "IF id: %s Ingress: %s" % (
                    self.NAME, self.LEN, self.iof_off, self.hof_off,
                    self.if_id, self.ingress))


class SCMPInfoRevocation(SCMPInfoPathOffsets):
    """Store IOF offset, HOF offset, IF id, ingress flag and Rev_info."""
    NAME = "SCMPInfoPktSize"
    STRUCT_FMT = "!HHH?x"
    LEN = struct.calcsize(STRUCT_FMT)
    ATTRIBS = ["iof_off", "hof_off", "if_id", "ingress"]

    @classmethod
    def from_pkt(cls, pkt, if_id, ingress, srev_info):
        rawRev = srev_info.pack()
        inst = cls()

        padding_length = calc_padding(inst.LEN + len(rawRev), LINE_LEN)
        rawRev += bytes(padding_length)

        iof_offset, hof_offset = inst._calc_offsets(pkt)
        inst._set_vals((iof_offset, hof_offset, if_id, ingress))
        inst.srev_info = rawRev
        return inst

    def _parse(self, raw):
        data = Raw(raw, self.NAME)
        self._set_vals(struct.unpack(self.STRUCT_FMT, data.pop(self.LEN)))
        self.srev_info = data.pop()

    def pack(self):  # pragma: no cover
        assert isinstance(self.srev_info, bytes), type(self.srev_info)
        return super().pack() + self.srev_info

    def __len__(self):
        return self.LEN + len(self.srev_info)

    def __str__(self):
        return ("%s(%dB): IOF offset:%sB HOF offset: %sB "
                "IF id: %s Ingress: %s Rev token: %s" % (
                    self.NAME, len(self), self.iof_off, self.hof_off,
                    self.if_id, self.ingress, hex_str(self.srev_info)))


class SCMPInfoExtIdx(SCMPInfoGeneric):
    """Store extension index."""
    NAME = "SCMPInfoExtIdx"
    STRUCT_FMT = "!B7x"
    LEN = struct.calcsize(STRUCT_FMT)
    ATTRIBS = ["ext_idx"]

    @classmethod
    def from_pkt(cls, _, ext_idx):  # pragma: no cover
        inst = cls()
        inst._set_vals((ext_idx, ))
        return inst

    def __str__(self):
        return "%s(%dB): Ext index: %s" % (self.NAME, self.LEN, self.ext_idx)


INFO_MAP = {
    SCMPInfoType.STRING: SCMPInfoString,
    SCMPInfoType.ECHO: SCMPInfoEcho,
    SCMPInfoType.PKT_SIZE: SCMPInfoPktSize,
    SCMPInfoType.PATH_OFFSETS: SCMPInfoPathOffsets,
    SCMPInfoType.REVOCATION: SCMPInfoRevocation,
    SCMPInfoType.EXT_IDX: SCMPInfoExtIdx,
}


def _get_scmp_info_cls(class_, type_):  # pragma: no cover
    info_type = scmp_get_info_type(class_, type_)
    return INFO_MAP.get(info_type)


def parse_scmp_info(class_, type_, raw):  # pragma: no cover
    if not raw:
        return None
    cls_ = _get_scmp_info_cls(class_, type_)
    return cls_(raw)


def build_scmp_info(class_, type_, pkt, *args, **kwargs):  # pragma: no cover
    cls_ = _get_scmp_info_cls(class_, type_)
    if not cls_:
        return None
    return cls_.from_pkt(pkt, *args, **kwargs)
