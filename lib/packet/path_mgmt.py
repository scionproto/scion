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
from lib.packet.packet_base import PayloadBase
from lib.packet.pcb import PathSegment
from lib.packet.scion import PacketType, SCIONPacket, SCIONHeader
from lib.packet.scion_addr import ISD_AD, SCIONAddr


class PathMgmtType:
    """
    Enum of path management packet types.
    """
    REQUEST = 0
    RECORDS = 1
    LEASES = 2
    REVOCATIONS = 3


class PathSegmentType(object):
    """
    PathSegmentType class, indicates a type of path request/reply.
    """
    UP = 0  # Request/Reply for up-paths
    DOWN = 1  # Request/Reply for down-paths
    CORE = 2  # Request/Reply for core-paths
    UP_DOWN = 3  # Request/Reply for up- and down-paths


class RevocationType(object):
    """
    Enum of revocation types.
    """
    UP_SEGMENT = 0
    DOWN_SEGMENT = 1
    CORE_SEGMENT = 2
    INTERFACE = 3
    HOP = 4


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
        PayloadBase.__init__(self)
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
        PayloadBase.parse(self, raw)
        (self.type, ) = struct.unpack("!B", raw[:1])
        raw = raw[1:]
        (self.src_isd, self.src_ad) = ISD_AD.from_raw(raw[:ISD_AD.LEN])
        raw = raw[ISD_AD.LEN:]
        (self.dst_isd, self.dst_ad) = ISD_AD.from_raw(raw[:ISD_AD.LEN])

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
        :type: int (PathSegmentType)
        :param src_isd, src_ad: address of the source AD
        :type: int
        :param dst_isd, dst_ad: address of the destination AD
        :type: int
        """
        info = PathSegmentInfo()
        info.type = pckt_type
        info.src_isd = src_isd
        info.src_ad = src_ad
        info.dst_isd = dst_isd
        info.dst_ad = dst_ad
        return info


class PathSegmentRecords(PayloadBase):
    """
    Path Record class used for sending list of down/up-paths. Paths are
    represented as objects of the PathSegment class. Type of a path is
    determined through info field (object of PathSegmentInfo).
    """
    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathSegmentRecords.

        :param raw:
        :type raw:
        """
        PayloadBase.__init__(self)
        self.info = None
        self.pcbs = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        PayloadBase.parse(self, raw)
        self.info = PathSegmentInfo(raw[:PathSegmentInfo.LEN])
        self.pcbs = PathSegment.deserialize(raw[PathSegmentInfo.LEN:])

    def pack(self):
        return self.info.pack() + PathSegment.serialize(self.pcbs)

    @classmethod
    def from_values(cls, info, pcbs):
        """
        Returns a Path Record with the values specified.

        :param info: type of the path segment records
        :type: PathSegmentInfo
        :param pcbs: list of path segments
        :type: list
        """
        rec = PathSegmentRecords()
        rec.info = info
        rec.pcbs = pcbs
        return rec


class LeaseInfo(PayloadBase):
    """
    Class containing necessary information for a path-segment lease.
    """
    LEN = 1 + ISD_AD.LEN + 4 + 32

    def __init__(self, raw=None):
        """
        Initialize an instance of the class LeaseInfo.

        :param raw:
        :type raw:
        """
        PayloadBase.__init__(self)
        self.seg_type = PathSegmentType.DOWN
        self.isd_id = 0
        self.ad_id = 0
        self.exp_time = 0
        self.seg_id = b""

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        PayloadBase.parse(self, raw)
        if len(raw) < LeaseInfo.LEN:
            logging.error("Not enough data to parse LeaseInfo")
            return
        (self.seg_type, ) = struct.unpack("!B", raw[:1])
        raw = raw[1:]
        (self.isd_id, self.ad_id) = ISD_AD.from_raw(raw[:ISD_AD.LEN])
        raw = raw[ISD_AD.LEN:]
        (self.exp_time, self.seg_id) = struct.unpack("!L32s", raw)

    def pack(self):
        return (struct.pack("!B", self.seg_type) +
                ISD_AD(self.isd_id, self.ad_id).pack() +
                struct.pack("!L32s", self.exp_time, self.seg_id))

    @classmethod
    def from_values(cls, seg_type, isd_id, ad_id, exp_time, seg_id):
        """
        Returns a LeaseInfo object with the specified values.

        :param seg_type: type of the segment (down or core)
        :type: int
        :param isd_id, ad_id: leasers isd and ad IDs
        :type: int
        :param exp_time: expiration for the lease
        :type: int
        :param seg_id: segment ID
        :type: bytes
        """
        info = LeaseInfo()
        info.seg_type = seg_type
        info.isd_id = isd_id
        info.ad_id = ad_id
        info.exp_time = exp_time
        info.seg_id = seg_id

        return info

    def __str__(self):
        return ("leaser: (%d, %d) seg_type: %d expires: %d ID:%s" %
                self.isd_id, self.ad_id, self.seg_type, self.exp_time,
                self.seg_id)


class PathSegmentLeases(PayloadBase):
    """
    PathSegment leases used to notify an authoritative path server about the
    caching of path-segments. A lease contains a timestamp and the segment id
    of the path segment being cached.
    """

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathSegmentLeases.

        :param raw:
        :type raw:
        """
        PayloadBase.__init__(self)
        self.nleases = 0  # The number of leases contained in this packet.
        self.leases = []  # List of leases. Tuples (TS, ID)

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        PayloadBase.parse(self, raw)
        self.nleases = struct.unpack("!B", raw[0:1])[0]
        offset = 1
        for _ in range(self.nleases):
            self.leases.append(LeaseInfo(raw[offset:offset + LeaseInfo.LEN]))
            offset += LeaseInfo.LEN

    def pack(self):
        data = struct.pack("!B", self.nleases)
        data += b"".join([linfo.pack() for linfo in self.leases])

        return data

    @classmethod
    def from_values(cls, nleases, leases):
        """
        Returns a PathSegmentLease with the given values.

        :param nleases: number of leases this packet contains
        :type: int
        :param leases: list of leases as tuples (isd, ad, timestamp, segment id)
        :type: list
        """
        assert nleases == len(leases)
        pkt = PathSegmentLeases()
        pkt.nleases = nleases
        pkt.leases = leases

        return pkt

    def __str__(self):
        s = "[PathSegmentLeases: N = %d]\n" % self.nleases
        for (isd, ad, ts, seg_id) in self.leases:
            s += "leaser: (%d, %d) expires: %d ID:%s\n" % (isd, ad, ts, seg_id)
        return s


class RevocationInfo(PayloadBase):
    """
    Class containing revocation information, such as type, revocation token and
    the proof (the next element in the revocation hash chain).
    Hop revocation needs a pair of revocation tokens and proofs.
    """
    MIN_LEN = 1 + 2 * 32
    MAX_LEN = 1 + 5 * 32

    def __init__(self, raw=None):
        """
        Initialize an instance of the class RevocationInfo.

        :param raw:
        :type raw:
        """
        PayloadBase.__init__(self)
        self.rev_type = RevocationType.DOWN_SEGMENT
        self.incl_seg_id = False
        self.incl_hop = False
        self.seg_id = b""
        self.rev_token1 = b""
        self.proof1 = b""
        self.rev_token2 = b""
        self.proof2 = b""

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        if len(raw) < RevocationInfo.MIN_LEN:
            logging.error("Not enough data to parse RevocationInfo")
            return

        flags = struct.unpack("!B", raw[0:1])[0]
        self.rev_type = flags & 0x7
        self.incl_seg_id = (flags >> 3) & 0x1
        self.incl_hop = (flags >> 4) & 0x1
        offset = 1
        if self.incl_seg_id:
            self.seg_id = struct.unpack("!32s", raw[offset:offset + 32])[0]
            offset += 32
        (self.rev_token1, self.proof1) = struct.unpack("!32s32s",
                                                       raw[offset:offset + 64])
        offset += 64
        if self.incl_hop:
            (self.rev_token2, self.proof2) = \
                struct.unpack("!32s32s", raw[offset:offset + 64])
            offset += 64
        self.raw = raw[:offset]
        self.parsed = True

    def pack(self):
        flags = (self.incl_hop << 4) | (self.incl_seg_id << 3) | self.rev_type
        data = struct.pack("!B", flags)
        if self.incl_seg_id:
            data += struct.pack("!32s", self.seg_id)
        data += struct.pack("!32s32s", self.rev_token1, self.proof1)
        if self.incl_hop:
            data += struct.pack("!32s32s", self.rev_token2, self.proof2)

        return data

    @classmethod
    def from_values(cls, rev_type, rev_token1, proof1, incl_seg_id=False,
                    seg_id=b"", incl_hop=False, rev_token2=b"", proof2=b""):
        """
        Returns a RevocationInfo object with the specified values.

        :param rev_type: type of the revocation info
        :type: int (RevocationType)
        :param rev_token1: revocation token of interface or path segment
        :type: bytes
        :param proof1: proof for rev_token1
        :type: bytes
        :param incl_seg_id: True if packet includes a segment id
        :type: Bool
        :param seg_id: segment ID of the revoked segment
        :type: bytes
        :param incl_hop: True if packet includes a hop revocation token
        :param rev_token2: revocation token for egress if (only for hop rev)
        :type: bytes
        :param proof2: proof for rev_token2
        :type: bytes
        """
        info = RevocationInfo()
        info.rev_type = rev_type
        info.rev_token1 = rev_token1
        info.proof1 = proof1
        info.incl_seg_id = incl_seg_id
        info.seg_id = seg_id
        info.incl_hop = incl_hop
        info.rev_token2 = rev_token2
        info.proof2 = proof2

        return info

    def __str__(self):
        s = ("[Revocation type: %d, incl_seg_id: %d, incl_hop: %d]\n" %
             (self.rev_type, self.incl_seg_id, self.incl_hop))
        if self.incl_seg_id:
            s += "SegmentID: %s\n" % (self.seg_id)
        s += "Token1: %s\nProof1: %s\n" % (self.rev_token1, self.proof1)
        if self.incl_hop:
            s += "Token2: %s\nProof2: %s" % (self.rev_token2, self.proof2)
        return s


class RevocationPayload(PayloadBase):
    """
    Payload for revocation messages. List of RevocationInfo objects.
    """
    def __init__(self, raw=None):
        """
        Initialize an instance of the class RevocationPayload.

        :param raw:
        :type raw:
        """
        PayloadBase.__init__(self)
        self.rev_infos = []

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        PayloadBase.parse(self, raw)
        dlen = len(raw)
        offset = 0
        while offset < dlen:
            info = RevocationInfo(raw[offset:offset + RevocationInfo.MAX_LEN])
            if not info.parsed:
                logging.error("RevocationPayload couldn't be parsed.")
                return
            self.rev_infos.append(info)
            offset += len(info)

    def pack(self):
        return b"".join([info.pack() for info in self.rev_infos])

    @classmethod
    def from_values(cls, rev_infos):
        """
        Returns a RevocationPayload object with the specified values.

        :param rev_infos: list of RevocationInfo objects
        :type: list
        """
        payload = RevocationPayload()
        payload.rev_infos = rev_infos

        return payload

    def add_rev_info(self, info):
        """
        Adds a revocation info to the list.
        """
        assert isinstance(info, RevocationInfo)
        self.rev_infos.append(info)

    def __str__(self):
        return "".join([str(info) + "\n" for info in self.rev_infos])


class PathMgmtPacket(SCIONPacket):
    """
    Container for all path management packets.
    """
    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathMgmtPacket.

        :param raw:
        :type raw:
        """
        SCIONPacket.__init__(self)
        self.type = 0

        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        # Get the type of the first byte of the payload and instantiate the
        # corresponding payload class.
        self.type = struct.unpack("!B", self.payload[0:1])[0]
        if self.type == PathMgmtType.REQUEST:
            self.payload = PathSegmentInfo(self.payload[1:])
        elif self.type == PathMgmtType.RECORDS:
            self.payload = PathSegmentRecords(self.payload[1:])
        elif self.type == PathMgmtType.LEASES:
            self.payload = PathSegmentLeases(self.payload[1:])
        elif self.type == PathMgmtType.REVOCATIONS:
            self.payload = RevocationPayload(self.payload[1:])
        else:
            logging.error("Unsupported path management type: %d", self.type)

    def pack(self):
        if not isinstance(self.payload, bytes):
            self.payload = struct.pack("!B", self.type) + self.payload.pack()
        return SCIONPacket.pack(self)

    @classmethod
    def from_values(cls, type, payload, path, src_addr, dst_addr):
        """
        Returns a PathMgmtPacket with the values specified.

        :param type: the type of the packet
        :type: class PathMgmtType
        :param payload: the payload of the packet
        :type: lib.packet.packet_base.PayloadBase
        :param path: the path of the packet
        :type: lib.packet.path.PathBase
        :param src_addr: source address (ISD_AD namedtuple for response)
        :type: lib.packet.scion_addr.SCIONAddr or lib.packet.scion_addr.ISD_AD
        :param dst_addr: destination address (ISD_AD namedtuple for request)
        :type: lib.packet.scion_addr.SCIONAddr or lib.packet.scion_addr.ISD_AD
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
        pkt.type = type
        pkt.payload = payload
        return pkt

    def __str__(self):
        return (("[PathMgmtPacket type: %d]\n" % self.type) + str(self.hdr) +
                "\n" + str(self.payload))
