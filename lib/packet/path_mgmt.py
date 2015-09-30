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

# SCION
from lib.errors import SCIONParseError
from lib.packet.packet_base import PayloadClass, SCIONPayloadBase
from lib.packet.pcb import PathSegment
from lib.packet.scion_addr import ISD_AD
from lib.util import Raw


class PathMgmtType(object):
    """
    Enum of path management packet types.
    """
    REQUEST = 0
    REPLY = 1
    REG = 2  # Path registration (sent by Beacon Server).
    SYNC = 3  # For records synchronization purposes (used by Path Servers).
    REVOCATION = 4
    IFSTATE_INFO = 5
    IFSTATE_REQ = 6


class PathSegmentType(object):
    """
    PathSegmentType class, indicates a type of path request/reply.
    """
    UP = 0  # Request/Reply for up-paths
    DOWN = 1  # Request/Reply for down-paths
    CORE = 2  # Request/Reply for core-paths
    UP_DOWN = 3  # Request/Reply for up- and down-paths

    @classmethod
    def to_str(cls, seg_type):
        str_map = {
            cls.UP: "UP", cls.DOWN: "DOWN",
            cls.CORE: "CORE", cls.UP_DOWN: "UP_DOWN"
        }
        return str_map[seg_type]


class PathMgmtPayloadBase(SCIONPayloadBase):
    PAYLOAD_CLASS = PayloadClass.PATH
    PAYLOAD_TYPE = None


class PathSegmentInfo(PathMgmtPayloadBase):
    """
    PathSegmentInfo class used in sending path requests/replies. May be nested
    under other path management payloads.
    """
    PAYLOAD_TYPE = PathMgmtType.REQUEST
    LEN = 1 + 2 * ISD_AD.LEN
    NAME = "PathSegmentInfo"

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathSegmentInfo.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.seg_type = 0
        self.src_isd = 0
        self.src_ad = 0
        self.dst_isd = 0
        self.dst_ad = 0
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, self.LEN)
        self.seg_type = data.pop(1)
        self.src_isd, self.src_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.dst_isd, self.dst_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))

    @classmethod
    def from_values(cls, seg_type, src_isd, src_ad, dst_isd, dst_ad):
        """
        Returns PathSegmentInfo with fields populated from values.
        :param pckt_type: type of request/reply
        :type: int (PathSegmentType)
        :param src_isd, src_ad: address of the source AD
        :type src_isd, src_ad: int
        :param dst_isd, dst_ad: address of the destination AD
        :type dst_isd, dst_ad: int
        """
        inst = cls()
        inst.seg_type = seg_type
        inst.src_isd = src_isd
        inst.src_ad = src_ad
        inst.dst_isd = dst_isd
        inst.dst_ad = dst_ad
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!B", self.seg_type))
        packed.append(ISD_AD(self.src_isd, self.src_ad).pack())
        packed.append(ISD_AD(self.dst_isd, self.dst_ad).pack())
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return "[%s(%dB): seg type:%s src isd/ad: %s/%s dst isd/ad: %s/%s]" % (
            self.NAME, len(self), self.seg_type, self.src_isd, self.src_ad,
            self.dst_isd, self.dst_ad,
        )


class PathSegmentRecords(PathMgmtPayloadBase):
    """
    Path Record class used for sending list of down/up-paths. Paths are
    represented as objects of the PathSegment class. Type of a path is
    determined through info field (object of PathSegmentInfo).
    """
    MIN_LEN = PathSegmentInfo.LEN + PathSegment.MIN_LEN

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathSegmentRecords.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.info = None
        self.pcbs = None
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self.info = PathSegmentInfo(data.pop(PathSegmentInfo.LEN))
        self.pcbs = PathSegment.deserialize(data.pop())

    @classmethod
    def from_values(cls, info, pcbs):
        """
        Returns a Path Record with the values specified.

        :param info: type of the path segment records
        :type info: PathSegmentInfo
        :param pcbs: list of path segments
        :type pcbs: list
        """
        assert isinstance(info, PathSegmentInfo)
        inst = cls()
        inst.info = info
        inst.pcbs = pcbs
        return inst

    def pack(self):
        packed = []
        packed.append(self.info.pack())
        packed.append(PathSegment.serialize(self.pcbs))
        return b"".join(packed)

    def __len__(self):
        l = len(self.info)
        for pcb in self.pcbs:
            l += len(pcb)
        return l

    def __str__(self):
        s = []
        s.append("%s(%dB):" % (self.NAME, len(self)))
        s.append("  %s" % self.info)
        for pcb in self.pcbs:
            s.append("  %s" % pcb)
        return "\n".join(s)


class PathRecordsReply(PathSegmentRecords):
    PAYLOAD_TYPE = PathMgmtType.REPLY
    NAME = "PathRecordsReply"


class PathRecordsReg(PathSegmentRecords):
    PAYLOAD_TYPE = PathMgmtType.REG
    NAME = "PathRecordsReg"


class PathRecordsSync(PathSegmentRecords):
    PAYLOAD_TYPE = PathMgmtType.SYNC
    NAME = "PathRecordsSync"


class RevocationInfo(PathMgmtPayloadBase):
    """
    Class containing revocation information, i.e., the revocation token.
    """
    PAYLOAD_TYPE = PathMgmtType.REVOCATION
    LEN = 32
    NAME = "RevocationInfo"

    def __init__(self, raw=None):
        """
        Initialize an instance of the class RevocationInfo.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.rev_token = b""

        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.rev_token = struct.unpack("!32s", data.pop(self.LEN))[0]

    @classmethod
    def from_values(cls, rev_token):
        """
        Returns a RevocationInfo object with the specified values.

        :param rev_token: revocation token of interface
        :type rev_token: bytes
        """
        inst = cls()
        inst.rev_token = rev_token
        return inst

    def pack(self):
        return struct.pack("!32s", self.rev_token)

    def __len__(self):
        return self.LEN

    def __str__(self):
        return "[Revocation Info: %s]" % (self.rev_token)


class IFStateInfo(object):
    """
    StateInfo is used by the beacon server to inform edge routers about any
    state changes of other edge routers. It contains the ID of the router, the
    state (up or down), and the current revocation token and proof.
    """
    LEN = 2 + 2 + RevocationInfo.LEN
    NAME = "IFStateInfo"

    def __init__(self, raw=None):
        self.if_id = 0
        self.state = 0
        self.rev_info = None

        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.if_id, self.state = struct.unpack("!HH", data.pop(4))
        self.rev_info = RevocationInfo(data.pop())

    @classmethod
    def from_values(cls, if_id, state, rev_token):
        """
        Returns a IFStateInfo object with the values specified.

        :param if_id: The IF ID of the corresponding router.
        :type if_id: int
        :param state: The state of the interface.
        :type state: bool
        :param rev_token: The current revocation token for the interface.
        :type rev_token: bytes
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

    def __str__(self):
        s = []
        s.append("[IFStateInfo if_id: %d, state: %d]" %
                 (self.if_id, self.state))
        s.append(str(self.rev_info))
        return "\n".join(s)


class IFStatePayload(PathMgmtPayloadBase):
    """
    Payload for state info messages. List of IFStateInfo objects.
    """
    PAYLOAD_TYPE = PathMgmtType.IFSTATE_INFO
    MIN_LEN = IFStateInfo.LEN
    NAME = "IFStatePayload"

    def __init__(self, raw=None):
        super().__init__()
        self.ifstate_infos = []

        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        while len(data) > 0:
            info = IFStateInfo(data.pop(IFStateInfo.LEN))
            self.ifstate_infos.append(info)

    def pack(self):
        packed = []
        for info in self.ifstate_infos:
            packed.append(info.pack())
        return b"".join(packed)

    @classmethod
    def from_values(cls, ifstate_infos):
        """
        Returns a IFStateInfo object with the specified values.
        :param ifstate_infos: list of IFStateInfo objects
        :type ifstate_infos: list
        """
        inst = cls()
        inst.ifstate_infos = ifstate_infos
        return inst

    def add_ifstate_info(self, info):
        """
        Adds a ifstate info to the list.
        """
        assert isinstance(info, IFStateInfo)
        self.ifstate_infos.append(info)

    def __len__(self):  # pragma: no cover
        return len(self.ifstate_infos) * IFStateInfo.LEN

    def __str__(self):
        return "\n".join([str(info) for info in self.ifstate_infos])


class IFStateRequest(PathMgmtPayloadBase):
    """
    IFStateRequest encapsulates a request for interface states from an ER to
    the BS.
    """
    PAYLOAD_TYPE = PathMgmtType.IFSTATE_REQ
    LEN = 2
    ALL_INTERFACES = 0
    NAME = "IFStateRequest"

    def __init__(self, raw=None):
        super().__init__()
        self.if_id = self.ALL_INTERFACES

        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.if_id = struct.unpack("!H", data.pop())[0]

    @classmethod
    def from_values(cls, if_id=ALL_INTERFACES):
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

    def __len__(self):
        return self.LEN

    def __str__(self):
        return "[IFStateRequest if_id: %d]" % self.if_id


def parse_pathmgmt_payload(type_, data):
    type_map = {
        PathMgmtType.REQUEST: (PathSegmentInfo, PathSegmentInfo.LEN),
        PathMgmtType.REPLY: (PathRecordsReply, None),
        PathMgmtType.REG: (PathRecordsReg, None),
        PathMgmtType.SYNC: (PathRecordsSync, None),
        PathMgmtType.REVOCATION: (RevocationInfo, RevocationInfo.LEN),
        PathMgmtType.IFSTATE_INFO: (IFStatePayload, None),
        PathMgmtType.IFSTATE_REQ: (IFStateRequest, IFStateRequest.LEN),
    }
    if type_ not in type_map:
        raise SCIONParseError("Unsupported path management type: %s", type_)
    handler, len_ = type_map[type_]
    return handler(data.pop(len_))
