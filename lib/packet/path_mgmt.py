"""
path_mgmt.py

Copyright 2015 ETH Zurich

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
"""
:mod:`path_mgmt` --- Path Management packets
=============================

Contains all the packet formats used for path management.
"""

from lib.packet.packet_base import PayloadBase
from lib.packet.pcb import PathSegment
from lib.packet.scion import (SCIONPacket, get_addr_from_type, PacketType,
    SCIONHeader)
import logging
import struct

from bitstring import BitArray
import bitstring


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
    SEGMENT = 0
    INTERFACE = 1
    HOP = 2


class PathSegmentInfo(PayloadBase):
    """
    PathSegmentInfo class used in sending path requests/replies.
    """
    LEN = 21

    def __init__(self, raw=None):
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
        bits = BitArray(bytes=raw)
        (self.type, self.src_isd, self.dst_isd, self.src_ad, self.dst_ad) = \
            bits.unpack("uintbe:8, uintbe:16, uintbe:16, uintbe:64, uintbe:64")

    def pack(self):
        """
        Returns PathSegmentInfo as a binary string.
        """
        return bitstring.pack("uintbe:8, uintbe:16, uintbe:16,"
                              "uintbe:64, uintbe:64", self.type,
                              self.src_isd, self.dst_isd,
                              self.src_ad, self.dst_ad).bytes

    @classmethod
    def from_values(cls, pckt_type, src_isd, dst_isd, src_ad, dst_ad):
        """
        Returns PathSegmentInfo with fields populated from values.
        :param pckt_type: type of request/reply
        :type int (PathSegmentType)
        :param src_isd, src_ad: address of the source AD
        :type int
        :param dst_isd, dst_ad: address of the destination AD
        :type int
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
        :type PathSegmentInfo
        :param pcbs: list of path segments
        :type list
        """
        rec = PathSegmentRecords()
        rec.info = info
        rec.pcbs = pcbs
        return rec


class PathSegmentLeases(PayloadBase):
    """
    PathSegment leases used to notify an authoritative path server about the
    caching of path-segments. A lease contains a timestamp and the segment id
    of the path segment being cached.
    """
    LEASE_LEN = 4 + 32

    def __init__(self, raw=None):
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
            (ts, seg_id) = struct.unpack("!L32s", raw[offset:offset +
                PathSegmentLeases.LEASE_LEN])
            self.leases.append((ts, seg_id))
            offset += PathSegmentLeases.LEASE_LEN

    def pack(self):
        data = struct.pack("!B", self.nleases)
        for (ts, seg_id) in self.leases:
            data += struct.pack("!L32s", ts, seg_id)

        return data

    @classmethod
    def from_values(cls, nleases, leases):
        """
        Returns a PathSegmentLease with the given values.

        :param nleases: number of leases this packet contains
        :type int
        :param leases: list of leases as tuples (timestamp, segment id)
        :type list
        """
        assert nleases == len(leases)
        pkt = PathSegmentLeases()
        pkt.nleases = nleases
        pkt.leases = leases

        return pkt


class RevocationInfo(PayloadBase):
    """
    Class containing revocation information, such as type, revocation token and
    the proof (the next element in the revocation hash chain).
    Hop revocation needs a pair of revocation tokens and proofs.
    """
    MIN_LEN = 1 + 2 * 32
    MAX_LEN = MIN_LEN + 32

    def __init__(self, raw=None):
        PayloadBase.__init__(self)
        self.rev_type = 0
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

        (self.rev_type, self.rev_token1, self.proof1) = \
            struct.unpack("!B32s32s", raw[:RevocationInfo.MIN_LEN])
        if self.rev_type == RevocationType.HOP:
            assert len(raw) == RevocationInfo.MAX_LEN
            (self.rev_token2, self.proof2) = struct.unpack("!32s32s", raw[65:])
            self.raw = raw[:]
        else:
            self.raw = raw[:RevocationInfo.MIN_LEN]

    def pack(self):
        data = struct.pack("!B32s32s", self.rev_type, self.rev_token1,
                           self.proof1)
        if self.rev_type == RevocationType.HOP:
            data += struct.pack("!32s32s", self.rev_token2, self.proof2)

        return data

    @classmethod
    def from_values(cls, rev_type, rev_token1, proof1,
                    rev_token2=b"", proof2=b""):
        """
        Returns a RevocationInfo object with the specified values.

        :param rev_type: type of the revocation info
        :type int (RevocationType)
        :param rev_token1: revocation token of interface or path segment
        :type bytes
        :param proof1: proof for rev_token1
        :type bytes
        :param rev_token2: revocation token for egress if (only for hop rev)
        :type bytes
        :param proof2: proof for rev_token2
        :type bytes
        """
        info = RevocationInfo()
        info.rev_type = rev_type
        info.rev_token1 = rev_token1
        info.proof1 = proof1
        info.rev_token2 = rev_token2
        info.proof2 = proof2

        return info

    def __str__(self):
        s = "[Revocation type: %d\n" % (self.rev_type)
        s += "Token1: %s\nProof1: %s\n" % (self.rev_token1, self.proof1)
        if self.rev_type == RevocationType.HOP:
            s += "Token2: %s\nProof2: %s" % (self.rev_token2, self.proof2)
        return s


class RevocationPayload(PayloadBase):
    """
    Payload for revocation messages. List of RevocationInfo objects.
    """
    def __init__(self, raw=None):
        PayloadBase.__init__(self)
        self.rev_infos = []

        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        dlen = len(raw)
        offset = 0
        while offset < dlen:
            info = RevocationInfo(raw[offset:offset + RevocationInfo.MAX_LEN])
            self.rev_infos.append(info)
            if info.rev_type == RevocationType.HOP:
                offset += RevocationInfo.MAX_LEN
            else:
                offset += RevocationInfo.MIN_LEN

    def pack(self):
        return b"".join([info.pack() for info in self.rev_infos])

    @classmethod
    def from_values(cls, rev_infos):
        """
        Returns a RevocationPayload object with the specified values.

        :param rev_infos: list of RevocationInfo objects
        :type list
        """
        payload = RevocationPayload()
        payload.rev_infos = rev_infos

        return payload

    def __str__(self):
        return "".join([str(info) + "\n" for info in self.rev_infos])


class PathMgmtPacket(SCIONPacket):
    """
    Container for all path management packets.
    """
    def __init__(self, raw=None):
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
    def from_values(cls, type, payload, path, src_addr=None, dst_addr=None):
        """
        Returns a PathMgmtPacket with the values specified.

        :param type: the type of the packet
        :type class PathMgmtType
        :param payload: the payload of the packet
        :type lib.packet.packet_base.PayloadBase
        :param path: the path of the packet
        :type lib.packet.path.PathBase
        :param src_addr: source address
        :type lib.packet.host_addr.HostAddr
        :param dst_addr: destination address
        :type lib.packet.host_addr.HostAddr
        """
        pkt = PathMgmtPacket()
        if src_addr is None:
            src_addr = get_addr_from_type(PacketType.PATH_MGMT)
        if dst_addr is None:
            dst_addr = get_addr_from_type(PacketType.PATH_MGMT)
        pkt.hdr = SCIONHeader.from_values(src_addr, dst_addr,
                                          PacketType.DATA, path)
        pkt.type = type
        pkt.payload = payload
        return pkt
