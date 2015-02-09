"""
pcb.py

Copyright 2014 ETH Zurich

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

from lib.packet.opaque_field import (SupportSignatureField, HopOpaqueField,
    SupportPCBField, SupportPeerField, ROTField, InfoOpaqueField)
from lib.packet.path import CorePath
from lib.packet.scion import (SCIONPacket, get_addr_from_type, PacketType,
    SCIONHeader)
import logging

from bitstring import BitArray
import bitstring


class Marking(object):
    """
    Base class for all marking objects.
    """
    def __init__(self):
        self.parsed = False
        self.raw = None

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        pass

    def pack(self):
        """
        Returns object as a binary string.
        """
        pass

    def __eq__(self, other):
        if type(other) is type(self):
            return self.raw == other.raw
        else:
            return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash(self.raw)


class PCBMarking(Marking):
    """
    Packs all fields for a specific PCB marking, which includes: the Autonomous
    Domain's ID, the SupportSignatureField, the HopOpaqueField, and the
    SupportPCBField.
    """
    LEN = 32

    def __init__(self, raw=None):
        Marking.__init__(self)
        self.ad_id = 0
        self.ssf = None
        self.hof = None
        self.spcbf = None
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < PCBMarking.LEN:
            logging.warning("PCBM: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw[:8])
        self.ad_id = bits.unpack("uintbe:64")[0]
        self.ssf = SupportSignatureField(raw[8:16])
        self.hof = HopOpaqueField(raw[16:24])
        self.spcbf = SupportPCBField(raw[24:32])
        self.parsed = True

    @classmethod
    def from_values(cls, ad_id=0, ssf=None, hof=None, spcbf=None):
        """
        Returns PCBMarking with fields populated from values.

        @param ad_id: Autonomous Domain's ID.
        @param ssf: SupportSignatureField object.
        @param hof: HopOpaqueField object.
        @param spcbf: SupportPCBField object.
        """
        pcbm = PCBMarking()
        pcbm.ad_id = ad_id
        pcbm.ssf = ssf
        pcbm.hof = hof
        pcbm.spcbf = spcbf
        return pcbm

    def pack(self):
        """
        Returns PCBMarking as a binary string.
        """
        return (bitstring.pack("uintbe:64", self.ad_id).bytes +
            self.ssf.pack() + self.hof.pack() + self.spcbf.pack())

    def __str__(self):
        pcbm_str = "[PCB Marking ad_id: %d]\n" % (self.ad_id)
        pcbm_str += str(self.ssf)
        pcbm_str += str(self.hof) + '\n'
        pcbm_str += str(self.spcbf)
        return pcbm_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.ad_id == other.ad_id and
                    self.ssf == other.ssf and
                    self.hof == other.hof and
                    self.spcbf == other.spcbf)
        else:
            return False


class PeerMarking(Marking):
    """
    Packs all fields for a specific peer marking.
    """
    LEN = 24

    def __init__(self, raw=None):
        Marking.__init__(self)
        self.ad_id = 0
        self.hof = None
        self.spf = None
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < PeerMarking.LEN:
            logging.warning("PM: Data too short for parsing, len: %u", dlen)
            return
        bits = BitArray(bytes=raw[0:8])
        self.ad_id = bits.unpack("uintbe:64")[0]
        self.hof = HopOpaqueField(raw[8:16])
        self.spf = SupportPeerField(raw[16:24])
        self.parsed = True

    @classmethod
    def from_values(cls, ad_id=0, hof=None, spf=None):
        """
        Returns PeerMarking with fields populated from values.

        @param ad_id: Autonomous Domain's ID.
        @param hof: HopOpaqueField object.
        @param spf: SupportPeerField object.
        """
        peer_marking = PeerMarking()
        peer_marking.ad_id = ad_id
        peer_marking.hof = hof
        peer_marking.spf = spf
        return peer_marking

    def pack(self):
        """
        Returns PeerMarking as a binary string.
        """
        return (bitstring.pack("uintbe:64", self.ad_id).bytes +
            self.hof.pack() + self.spf.pack())

    def __str__(self):
        pm_str = "[Peer Marking ad_id: %x]\n" % (self.ad_id)
        pm_str += str(self.hof) + '\n'
        pm_str += str(self.spf)
        return pm_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.ad_id == other.ad_id and
                    self.hof == other.hof and
                    self.spf == other.spf)
        else:
            return False


class ADMarking(Marking):
    """
    Packs all fields for a specific Autonomous Domain.
    """
    LEN = PCBMarking.LEN

    def __init__(self, raw=None):
        Marking.__init__(self)
        self.pcbm = None
        self.pms = []
        self.sig = b''
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < ADMarking.LEN:
            logging.warning("AD: Data too short for parsing, len: %u", dlen)
            return
        self.pcbm = PCBMarking(raw[:PCBMarking.LEN])
        raw = raw[PCBMarking.LEN:]
        while len(raw) > (self.pcbm.ssf.sig_len):
            peer_marking = PeerMarking(raw[:PeerMarking.LEN])
            self.pms.append(peer_marking)
            raw = raw[PeerMarking.LEN:]
        self.sig = raw
        self.parsed = True

    @classmethod
    def from_values(cls, pcbm=None, pms=None, sig=b''):
        """
        Returns ADMarking with fields populated from values.

        @param pcbm: PCBMarking object.
        @param pms: List of PeerMarking objects.
        @param sig: Beacon's signature.
        """
        ad_marking = ADMarking()
        ad_marking.pcbm = pcbm
        ad_marking.pms = []
        if pms is not None:
            ad_marking.pms = pms
        ad_marking.sig = sig
        return ad_marking

    def pack(self):
        """
        Returns ADMarking as a binary string.
        """
        ad_bytes = self.pcbm.pack()
        for peer_marking in self.pms:
            ad_bytes += peer_marking.pack()
        ad_bytes += self.sig
        return ad_bytes

    def remove_signature(self):
        """
        Removes the signature from the AD block.
        """
        self.sig = b''
        self.pcbm.ssf.sig_len = 0

    def __str__(self):
        ad_str = "[Autonomous Domain]\n"
        ad_str += str(self.pcbm)
        for peer_marking in self.pms:
            ad_str += str(peer_marking)
        ad_str += str(self.sig) + "\n"
        return ad_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.pcbm == other.pcbm and
                    self.pms == other.pms and
                    self.sig == other.sig)
        else:
            return False


class PathSegment(Marking):
    """
    Packs all PathSegment fields for a specific beacon.
    """
    LEN = 16

    def __init__(self, raw=None):
        Marking.__init__(self)
        self.iof = None
        self.rotf = None
        self.ads = []
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw
        dlen = len(raw)
        if dlen < PathSegment.LEN:
            logging.warning("PathSegment: Data too short for parsing, " +
            "len: %u", dlen)
            return
        self.iof = InfoOpaqueField(raw[0:8])
        self.rotf = ROTField(raw[8:16])
        raw = raw[16:]
        while len(raw) > 0:
            pcbm = PCBMarking(raw[:PCBMarking.LEN])
            ad_marking = ADMarking(raw[:pcbm.ssf.sig_len + pcbm.ssf.block_size])
            self.ads.append(ad_marking)
            raw = raw[pcbm.ssf.sig_len + pcbm.ssf.block_size:]
        self.parsed = True

    def pack(self):
        """
        Returns PathSegment as a binary string.
        """
        pcb_bytes = self.iof.pack() + self.rotf.pack()
        for ad_marking in self.ads:
            pcb_bytes += ad_marking.pack()
        return pcb_bytes

    def add_ad(self, ad_marking):
        """
        Appends a new AD block.
        """
        self.iof.hops = self.iof.hops + 1
        self.ads.append(ad_marking)

    def remove_signatures(self):
        """
        Removes the signature from each AD block.
        """
        for ad_marking in self.ads:
            ad_marking.remove_signature()

    def get_path(self, reverse_direction=False):
        """
        Returns the list of HopOpaqueFields in the path.
        """
        hofs = []
        if reverse_direction:
            ads = list(reversed(self.ads))
            self.iof.up_flag = self.iof.up_flag ^ True
        else:
            ads = self.ads
        for ad_marking in ads:
            hofs.append(ad_marking.pcbm.hof)
        core_path = CorePath.from_values(self.iof, hofs)
        return core_path

    def get_isd(self):
        """
        Returns the ISD ID.
        """
        return self.iof.isd_id

    def get_last_ad(self):
        """
        Returns the PCBMarking belonging to the last AD on the path.
        """
        if self.ads:
            return self.ads[-1].pcbm
        else:
            return None

    def get_first_ad(self):
        """
        Returns the PCBMarking belonging to the first AD on the path.
        """
        if self.ads:
            return self.ads[0].pcbm
        else:
            return None

    def compare_hops(self, other):
        """
        Compares the (AD-level) hops of two half-paths. Returns true if all hops
        are identical and false otherwise.
        """
        if not isinstance(other, PathSegment):
            return False

        self_hops = [ad.pcbm.ad_id for ad in self.ads]
        other_hops = [ad.pcbm.ad_id for ad in other.ads]

        return self_hops == other_hops

    @staticmethod
    def deserialize(raw):
        """
        Deserializes a bytes string into a list of PathSegments.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < PathSegment.LEN:
            logging.warning("HPB: Data too short for parsing, len: %u", dlen)
            return
        pcbs = []
        while len(raw) > 0:
            pcb = PathSegment()
            pcb.iof = InfoOpaqueField(raw[0:8])
            pcb.rotf = ROTField(raw[8:16])
            raw = raw[16:]
            for _ in range(pcb.iof.hops):
                pcbm = PCBMarking(raw[:PCBMarking.LEN])
                ad_marking = ADMarking(raw[:pcbm.ssf.sig_len +
                    pcbm.ssf.block_size])
                pcb.ads.append(ad_marking)
                raw = raw[pcbm.ssf.sig_len + pcbm.ssf.block_size:]
            pcbs.append(pcb)
        return pcbs

    @staticmethod
    def serialize(pcbs):
        """
        Serializes a list of PathSegments into a bytes string.
        """
        pcbs_list = []
        for pcb in pcbs:
            pcbs_list.append(pcb.pack())
        return b"".join(pcbs_list)

    def __str__(self):
        pcb_str = "[PathSegment]\n"
        pcb_str += str(self.iof) + str(self.rotf)
        for ad_marking in self.ads:
            pcb_str += str(ad_marking)
        return pcb_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.iof == other.iof and
                    self.rotf == other.rotf and
                    self.ads == other.ads)
        else:
            return False


class PathConstructionBeacon(SCIONPacket):
    """
    PathConstructionBeacon packet, used for path propagation.
    """
    def __init__(self, raw=None):
        SCIONPacket.__init__(self)
        self.pcb = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        self.pcb = PathSegment(self.payload)

    @classmethod
    def from_values(cls, dst, pcb):
        """
        Returns a PathConstructionBeacon packet with the values specified.

        @param dst: Destination address (must be a 'HostAddr' object)
        @param pcb: Path Construction PathConstructionBeacon ('PathSegment'
                    class)
        """
        beacon = PathConstructionBeacon()
        beacon.pcb = pcb
        src = get_addr_from_type(PacketType.BEACON)
        beacon.hdr = SCIONHeader.from_values(src, dst, PacketType.DATA)
        return beacon

    def pack(self):
        self.payload = self.pcb.pack()
        return SCIONPacket.pack(self)


class PathSegmentType(object):
    """
    PathSegmentType class, indicates a type of path request/reply.
    """
    UP = 0  # Request/Reply for up-paths
    DOWN = 1  # Request/Reply for down-paths
    CORE = 2  # Request/Reply for core-paths
    UP_DOWN = 3  # Request/Reply for up- and down-paths


class PathSegmentInfo(object):
    """
    PathSegmentInfo class used in sending path requests/replies.
    """
    LEN = 21

    def __init__(self, raw=None):
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
        @param pckt_type: type of request/reply
                          (must be 'PathSegmentType' object)
        @param src_isd, src_ad: address of the source AD
        @param dst_isd, dst_ad: address of targeted AD
        """
        info = PathSegmentInfo()
        info.type = pckt_type
        info.src_isd = src_isd
        info.src_ad = src_ad
        info.dst_isd = dst_isd
        info.dst_ad = dst_ad
        return info


class PathSegmentRequest(SCIONPacket):
    """
    Path Request packet.
    """
    def __init__(self, raw=None):
        SCIONPacket.__init__(self)
        self.info = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        self.info = PathSegmentInfo(self.payload)

    @classmethod
    def from_values(cls, src, info, path=None):
        """
        Returns a Path Request with the values specified.

        @param src: Source address (must be a 'HostAddr' object)
        @param info: determines type of a path request
                     (object of 'PathSegmentInfo')
        @param path: path to a core or None (when request is local)
        """
        req = PathSegmentRequest()
        dst = get_addr_from_type(PacketType.PATH_REQ)
        req.hdr = SCIONHeader.from_values(src, dst, PacketType.DATA, path=path)
        req.payload = info.pack()
        req.info = info
        return req

    def pack(self):
        self.payload = self.info.pack()
        return SCIONPacket.pack(self)


class PathSegmentRecords(SCIONPacket):
    """
    Path Record class used for sending list of down/up-paths. Paths are
    represented as objects of the PathSegment class. Type of a path is
    determined through info field (object of PathSegmentInfo).
    """
    def __init__(self, raw=None):
        SCIONPacket.__init__(self)
        self.info = None
        self.pcbs = None
        if raw:
            self.parse(raw)

    def parse(self, raw):
        SCIONPacket.parse(self, raw)
        self.info = PathSegmentInfo(self.payload[:PathSegmentInfo.LEN])
        self.pcbs = PathSegment.deserialize(self.payload[PathSegmentInfo.LEN:])

    @classmethod
    def from_values(cls, dst, info, pcbs, path=None):
        """
        Returns a Path Record with the values specified.

        @param info: determines type of a path record
                     (object of 'PathSegmentInfo')
        @param dst: Destination address (must be a 'HostAddr' object)
        @param path: path to a core or None (when reply is local)
        """
        rec = PathSegmentRecords()
        src = get_addr_from_type(PacketType.PATH_REC)
        rec.hdr = SCIONHeader.from_values(src, dst, PacketType.DATA, path=path)
        rec.payload = b"".join([info.pack(), PathSegment.serialize(pcbs)])
        rec.info = info
        rec.pcbs = pcbs
        return rec
