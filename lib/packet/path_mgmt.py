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
:mod:`path_mgmt` --- Path Management packets
============================================

Contains all the packet formats used for path management.
"""
# Stdlib
import struct
from collections import defaultdict

# SCION
from lib.types import PathMgmtType as PMT, PathSegmentType as PST
from lib.errors import SCIONParseError
from lib.flagtypes import PathSegFlags as PSF
from lib.packet.packet_base import PathMgmtPayloadBase
from lib.packet.pcb import PathSegment
from lib.packet.scion_addr import ISD_AS
from lib.packet.rev_info import RevocationInfo
from lib.util import Raw


class PathSegmentReq(PathMgmtPayloadBase):
    """Describes a request for path segment(s)"""
    NAME = "PathSegmentReq"
    PAYLOAD_TYPE = PMT.REQUEST
    LEN = 1 + 2 * ISD_AS.LEN

    def __init__(self, raw=None):  # pragma: no cover
        super().__init__()
        self.flags = 0
        self.src_ia = None
        self.dst_ia = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, self.LEN)
        self.flags = data.pop(1)
        self.src_ia = ISD_AS(data.pop(ISD_AS.LEN))
        self.dst_ia = ISD_AS(data.pop(ISD_AS.LEN))

    @classmethod
    def from_values(cls, src_ia, dst_ia, flags=0):  # pragma: no cover
        """
        Returns PathSegmentReq with fields populated from values.

        :params int flags: PathSegmentFlags values
        """
        assert isinstance(src_ia, ISD_AS)
        assert isinstance(dst_ia, ISD_AS)
        assert isinstance(flags, int)
        inst = cls()
        inst.flags = flags
        inst.src_ia = src_ia
        inst.dst_ia = dst_ia
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.flags))
        packed.append(self.src_ia.pack())
        packed.append(self.dst_ia.pack())
        return b"".join(packed)

    def short_desc(self):  # pragma: no cover
        return "%s -> %s. Flags: %s" % (
            self.src_ia, self.dst_ia, PSF.to_str(self.flags))

    def sibra(self):  # pragma: no cover
        return bool(self.flags & PSF.SIBRA)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return "%s(%dB): %s" % (self.NAME, len(self), self.short_desc())


class PathSegmentRecords(PathMgmtPayloadBase):
    """
    Path Record class used for sending list of down/up-paths. Paths are
    represented as objects of the PathSegment class.
    """
    MIN_LEN = 1 + PathSegment.MIN_LEN

    def __init__(self, raw=None):  # pragma: no cover
        super().__init__()
        self.pcbs = defaultdict(list)
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        while data:
            seg_type = data.pop(1)
            pcb = PathSegment(data.get())
            data.pop(len(pcb))
            self.pcbs[seg_type].append(pcb)

    @classmethod
    def from_values(cls, pcb_dict):  # pragma: no cover
        """
        Returns a Path Record with the values specified.

        :param pcb_dict: dict of {seg_type: pcbs}
        """
        inst = cls()
        inst.pcbs.update(pcb_dict)
        return inst

    def pack(self):
        packed = []
        for seg_type, pcbs in self.pcbs.items():
            for pcb in pcbs:
                packed.append(struct.pack("!B", seg_type))
                packed.append(pcb.pack())
        return b"".join(packed)

    def __len__(self):
        l = 0
        for pcbs in self.pcbs.values():
            for pcb in pcbs:
                l += len(pcb) + 1  # segment type byte
        return l

    def __str__(self):
        s = []
        s.append("%s(%dB):" % (self.NAME, len(self)))
        for type_ in [PST.UP, PST.DOWN, PST.CORE]:
            if self.pcbs[type_]:
                s.append("  %s:" % PST.to_str(type_))
                for pcb in self.pcbs[type_]:
                    s.append("    %s" % pcb.short_desc())
        return "\n".join(s)


class PathRecordsReply(PathSegmentRecords):
    NAME = "PathRecordsReply"
    PAYLOAD_TYPE = PMT.REPLY


class PathRecordsReg(PathSegmentRecords):
    NAME = "PathRecordsReg"
    PAYLOAD_TYPE = PMT.REG


class PathRecordsSync(PathSegmentRecords):
    NAME = "PathRecordsSync"
    PAYLOAD_TYPE = PMT.SYNC


class IFStateInfo(object):
    """
    StateInfo is used by the beacon server to inform edge routers about any
    state changes of other edge routers. It contains the ID of the router, the
    state (up or down), and the current revocation token and proof.
    """
    NAME = "IFStateInfo"
    LEN = 2 + 2 + RevocationInfo.LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.if_id = 0
        self.state = 0
        self.rev_info = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.if_id, self.state = struct.unpack("!HH", data.pop(4))
        self.rev_info = RevocationInfo(data.pop())

    @classmethod
    def from_values(cls, if_id, state, rev_token):  # pragma: no cover
        """
        Returns a IFStateInfo object with the values specified.

        :param int if_id: The IF ID of the corresponding router.
        :param bool state: The state of the interface.
        :param bytes rev_token: The current revocation token for the interface.
        """
        assert isinstance(rev_token, bytes)
        inst = cls()
        inst.if_id = if_id
        inst.state = state
        inst.rev_info = RevocationInfo.from_values(rev_token)
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!HH", self.if_id, self.state))
        packed.append(self.rev_info.pack())
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        s = []
        s.append("%s(%dB): if_id: %d, state: %d" %
                 (self.NAME, len(self), self.if_id, self.state))
        s.append("  %s" % self.rev_info)
        return "\n".join(s)


class IFStatePayload(PathMgmtPayloadBase):
    """
    Payload for state info messages. List of IFStateInfo objects.
    """
    NAME = "IFStatePayload"
    PAYLOAD_TYPE = PMT.IFSTATE_INFO
    MIN_LEN = IFStateInfo.LEN

    def __init__(self, raw=None):  # pragma: no cover
        super().__init__()
        self.ifstate_infos = []
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        while len(data) > 0:
            info = IFStateInfo(data.pop(IFStateInfo.LEN))
            self.ifstate_infos.append(info)

    @classmethod
    def from_values(cls, ifstate_infos):  # pragma: no cover
        """
        Returns a IFStateInfo object with the specified values.
        :param ifstate_infos: list of IFStateInfo objects
        :type ifstate_infos: list
        """
        inst = cls()
        inst.ifstate_infos = ifstate_infos
        return inst

    def pack(self):
        packed = []
        for info in self.ifstate_infos:
            packed.append(info.pack())
        return b"".join(packed)

    def add_ifstate_info(self, info):  # pragma: no cover
        """
        Adds a ifstate info to the list.
        """
        assert isinstance(info, IFStateInfo)
        self.ifstate_infos.append(info)

    def __len__(self):  # pragma: no cover
        return len(self.ifstate_infos) * IFStateInfo.LEN

    def __str__(self):
        s = []
        s.append("%s(%dB):" % (self.NAME, len(self)))
        for info in self.ifstate_infos:
            s.append("  %s" % info)
        return "\n".join(s)


class IFStateRequest(PathMgmtPayloadBase):
    """
    IFStateRequest encapsulates a request for interface states from an ER to
    the BS.
    """
    NAME = "IFStateRequest"
    PAYLOAD_TYPE = PMT.IFSTATE_REQ
    LEN = 2
    ALL_INTERFACES = 0

    def __init__(self, raw=None):  # pragma: no cover
        super().__init__()
        self.if_id = self.ALL_INTERFACES
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.if_id = struct.unpack("!H", data.pop())[0]

    @classmethod
    def from_values(cls, if_id=ALL_INTERFACES):  # pragma: no cover
        """
        Returns a IFStateRequest object with the specified values.
        :param if_id: The if_id of interest.
        :type if_id: int
        """
        inst = cls()
        inst.if_id = if_id
        return inst

    def pack(self):
        return struct.pack("!H", self.if_id)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return "%s(%sB): if_id: %s" % (self.NAME, len(self), self.if_id)


_TYPE_MAP = {
    PMT.REQUEST: (PathSegmentReq, PathSegmentReq.LEN),
    PMT.REPLY: (PathRecordsReply, None),
    PMT.REG: (PathRecordsReg, None),
    PMT.SYNC: (PathRecordsSync, None),
    PMT.REVOCATION: (RevocationInfo, RevocationInfo.LEN),
    PMT.IFSTATE_INFO: (IFStatePayload, None),
    PMT.IFSTATE_REQ: (IFStateRequest, IFStateRequest.LEN),
}


def parse_pathmgmt_payload(type_, data):
    if type_ not in _TYPE_MAP:
        raise SCIONParseError("Unsupported path management type: %s", type_)
    handler, len_ = _TYPE_MAP[type_]
    return handler(data.pop(len_))
