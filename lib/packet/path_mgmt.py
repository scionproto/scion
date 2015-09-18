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
import logging
import struct

# SCION
from lib.errors import SCIONParseError
from lib.packet.packet_base import PayloadBase
from lib.packet.pcb import PathSegment
from lib.packet.scion import PacketType, SCIONPacket, SCIONHeader
from lib.packet.scion_addr import ISD_AD, SCIONAddr
from lib.util import Raw


class PathMgmtType(object):
    """
    Enum of path management packet types.
    """
    REQUEST = 0
    RECORDS = 1
    REVOCATION = 2
    IFSTATE_INFO = 3
    IFSTATE_REQ = 4


class PathSegmentType(object):
    """
    PathSegmentType class, indicates a type of path request/reply.
    """
    UP = 0  # Request/Reply for up-paths
    DOWN = 1  # Request/Reply for down-paths
    CORE = 2  # Request/Reply for core-paths
    UP_DOWN = 3  # Request/Reply for up- and down-paths


class PathSegmentInfo(PayloadBase):
    """
    PathSegmentInfo class used in sending path requests/replies.
    """
    LEN = 1 + 2 * ISD_AD.LEN

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathSegmentInfo.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.type = 0
        self.src_isd = 0
        self.dst_isd = 0
        self.src_ad = 0
        self.dst_ad = 0
        if raw:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        super().parse(raw)
        data = Raw(raw, "PathSegmentInfo", self.LEN)
        self.type = data.pop(1)
        self.src_isd, self.src_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.dst_isd, self.dst_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))

    def pack(self):
        """
        Returns PathSegmentInfo as a binary string.
        """
        return (struct.pack("B", self.type) +
                ISD_AD(self.src_isd, self.src_ad).pack() +
                ISD_AD(self.dst_isd, self.dst_ad).pack())

    @classmethod
    def from_values(cls, pckt_type, src_isd, dst_isd, src_ad, dst_ad):
        """
        Returns PathSegmentInfo with fields populated from values.
        :param pckt_type: type of request/reply
        :type pckt_type: int (PathSegmentType)
        :param src_isd, src_ad: address of the source AD
        :type src_isd, src_ad: int
        :param dst_isd, dst_ad: address of the destination AD
        :type dst_isd, dst_ad: int
        """
        info = PathSegmentInfo()
        info.type = pckt_type
        info.src_isd = src_isd
        info.src_ad = src_ad
        info.dst_isd = dst_isd
        info.dst_ad = dst_ad
        return info

    def __len__(self):
        return self.LEN


class PathSegmentRecords(PayloadBase):
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
        if raw:
            self.parse(raw)

    def parse(self, raw):
        super().parse(raw)
        data = Raw(raw, "PathSegmentRecords", self.MIN_LEN, min_=True)
        self.info = PathSegmentInfo(data.pop(PathSegmentInfo.LEN))
        self.pcbs = PathSegment.deserialize(data.pop())

    def pack(self):
        return self.info.pack() + PathSegment.serialize(self.pcbs)

    @classmethod
    def from_values(cls, info, pcbs):
        """
        Returns a Path Record with the values specified.

        :param info: type of the path segment records
        :type info: PathSegmentInfo
        :param pcbs: list of path segments
        :type pcbs: list
        """
        rec = PathSegmentRecords()
        rec.info = info
        rec.pcbs = pcbs
        return rec


class RevocationInfo(PayloadBase):
    """
    Class containing revocation information, i.e., the revocation token.
    """
    LEN = 32

    def __init__(self, raw=None):
        """
        Initialize an instance of the class RevocationInfo.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.rev_token = b""

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        super().parse(raw)
        data = Raw(raw, "RevocationInfo", self.LEN)
        self.rev_token = struct.unpack("!32s", data.pop(self.LEN))[0]

    def pack(self):
        return struct.pack("!32s", self.rev_token)

    @classmethod
    def from_values(cls, rev_token):
        """
        Returns a RevocationInfo object with the specified values.

        :param rev_token: revocation token of interface
        :type rev_token: bytes
        """
        info = cls()
        info.rev_token = rev_token

        return info

    def __str__(self):
        return "[Revocation Info: %s]" % (self.rev_token)

    def __len__(self):  # pragma: no cover
        return self.LEN


class IFStateInfo(PayloadBase):
    """
    StateInfo is used by the beacon server to inform edge routers about any
    state changes of other edge routers. It contains the ID of the router, the
    state (up or down), and the current revocation token and proof.
    """
    LEN = 2 + 2 + RevocationInfo.LEN

    def __init__(self, raw=None):
        super().__init__()
        self.if_id = 0
        self.state = 0
        self.rev_info = None

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        super().parse(raw)
        data = Raw(raw, "IFStateInfo", self.LEN)
        self.if_id, self.state = struct.unpack("!HH", data.pop(4))
        self.rev_info = RevocationInfo(data.pop())

    def pack(self):
        return struct.pack("!HH", self.if_id, self.state) + self.rev_info.pack()

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
        info = cls()
        info.if_id = if_id
        info.state = state
        info.rev_info = RevocationInfo.from_values(rev_token)

        return info

    def __str__(self):
        s = "[IFStateInfo if_id: %d, state: %d]\n" % (self.if_id, self.state)
        s += str(self.rev_info)
        return s

    def __len__(self):  # pragma: no cover
        return self.LEN


class IFStatePayload(PayloadBase):
    """
    Payload for state info messages. List of IFStateInfo objects.
    """
    MIN_LEN = IFStateInfo.LEN

    def __init__(self, raw=None):
        super().__init__()
        self.ifstate_infos = []

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        super().parse(raw)
        data = Raw(raw, "IFStatePayload", self.MIN_LEN, min_=True)
        while len(data) > 0:
            info = IFStateInfo(data.get(IFStateInfo.LEN))
            self.ifstate_infos.append(info)
            data.pop(IFStateInfo.LEN)

    def pack(self):
        return b"".join([info.pack() for info in self.ifstate_infos])

    @classmethod
    def from_values(cls, ifstate_infos):
        """
        Returns a IFStateInfo object with the specified values.
        :param ifstate_infos: list of IFStateInfo objects
        :type ifstate_infos: list
        """
        payload = cls()
        payload.ifstate_infos = ifstate_infos

        return payload

    def add_ifstate_info(self, info):
        """
        Adds a ifstate info to the list.
        """
        assert isinstance(info, IFStateInfo)
        self.ifstate_infos.append(info)

    def __str__(self):
        return "".join([str(info) + "\n" for info in self.ifstate_infos])

    def __len__(self):
        return len(self.ifstate_infos) * IFStateInfo.LEN


class IFStateRequest(PayloadBase):
    """
    IFStateRequest encapsulates a request for interface states from an ER to
    the BS.
    """
    LEN = 2
    ALL_INTERFACES = 0

    def __init__(self, raw=None):
        super().__init__()
        self.if_id = self.ALL_INTERFACES

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        super().parse(raw)
        data = Raw(raw, "IFStateRequest", self.LEN)
        self.if_id = struct.unpack("!H", data.pop())[0]

    def pack(self):
        return struct.pack("!H", self.if_id)

    @classmethod
    def from_values(cls, if_id=ALL_INTERFACES):
        """
        Returns a IFStateRequest object with the specified values.
        :param if_id: The if_id of interest.
        :type if_id: int
        """
        payload = cls()
        payload.if_id = if_id

        return payload

    def __str__(self):
        return "[IFStateRequest if_id: %d]" % self.if_id

    def __len__(self):  # pragma: no cover
        return self.LEN


class PathMgmtPacket(SCIONPacket):
    """
    Container for all path management packets.
    """
    MIN_LEN = 1 + min(PathSegmentInfo.LEN,
                      PathSegmentRecords.MIN_LEN,
                      RevocationInfo.LEN,
                      IFStatePayload.MIN_LEN,
                      IFStateRequest.LEN,)

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathMgmtPacket.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.type = 0

        if raw:
            self.parse(raw)

    def parse(self, raw):
        super().parse(raw)
        data = Raw(self.get_payload(), "PathMgmtPacket", self.MIN_LEN,
                   min_=True)
        # Get the type of the first byte of the payload and instantiate the
        # corresponding payload class.
        self.type = data.pop(1)
        if self.type == PathMgmtType.REQUEST:
            self.set_payload(PathSegmentInfo(data.pop(PathSegmentInfo.LEN)))
        elif self.type == PathMgmtType.RECORDS:
            self.set_payload(PathSegmentRecords(data.pop()))
        elif self.type == PathMgmtType.REVOCATION:
            self.set_payload(RevocationInfo(data.pop()))
        elif self.type == PathMgmtType.IFSTATE_INFO:
            self.set_payload(IFStatePayload(data.pop()))
        elif self.type == PathMgmtType.IFSTATE_REQ:
            self.set_payload(IFStateRequest(data.pop()))
        else:
            raise SCIONParseError("Unsupported path management type: %d",
                                  self.type)

    def pack(self):
        if not isinstance(self._payload, bytes):
            self.set_payload(struct.pack("!B", self.type) +
                             self._payload.pack())
        return super().pack()

    @classmethod
    def from_values(cls, type_, payload, path, src_addr, dst_addr):
        """
        Returns a PathMgmtPacket with the values specified.

        :param type_: the type of the packet
        :type type_:  PathMgmtType
        :param payload: the payload of the packet
        :type payload: lib.packet.packet_base.PayloadBase
        :param path: the path of the packet
        :type path: lib.packet.path.PathBase
        :param src_addr: source address (ISD_AD namedtuple for response)
        :type src_addr: lib.packet.scion_addr.SCIONAddr or
                        lib.packet.scion_addr.ISD_AD
        :param dst_addr: destination address (ISD_AD namedtuple for request)
        :type dst_addr: lib.packet.scion_addr.SCIONAddr or
                        lib.packet.scion_addr.ISD_AD
        """
        pkt = PathMgmtPacket()
        if isinstance(src_addr, ISD_AD) and isinstance(dst_addr, SCIONAddr):
            src_addr = SCIONAddr.from_values(src_addr.isd, src_addr.ad,
                                             PacketType.PATH_MGMT)
        elif isinstance(src_addr, SCIONAddr) and isinstance(dst_addr, ISD_AD):
            dst_addr = SCIONAddr.from_values(dst_addr.isd, dst_addr.ad,
                                             PacketType.PATH_MGMT)
        else:
            logging.error("Unsupported src_addr, dst_addr pair.")
        pkt.hdr = SCIONHeader.from_values(src_addr, dst_addr, path)
        pkt.type = type_
        pkt.set_payload(payload)
        return pkt

    @classmethod
    def with_header(cls, type_, payload, header):
        """
        Returns a PathMgmtPacket with the values specified.

        :param type_: the type of the packet
        :type type_: class PathMgmtType
        :param payload: The payload of the packet
        :type payload: lib.packet.packet_base.PayloadBase
        :param header: The header of the packet.
        :type header: lib.packet.scion.SCIONHeader
        """
        pkt = PathMgmtPacket()
        pkt.hdr = header
        pkt.type = type_
        pkt.set_payload(payload)
        return pkt

    def __str__(self):
        return (("[PathMgmtPacket type: %d]\n" % self.type) + str(self.hdr) +
                "\n" + str(self._payload))
