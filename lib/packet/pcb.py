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
:mod:`pcb` --- SCION Beacon
===========================
"""
# Stdlib
import base64
import copy
import logging
import struct

# External packages
from Crypto.Hash import SHA256

# SCION
from lib.defines import EXP_TIME_UNIT
from lib.packet.opaque_field import (
    HopOpaqueField,
    InfoOpaqueField,
    SupportPeerField,
    SupportSignatureField,
    TRCField,
)
from lib.packet.path import CorePath
from lib.packet.scion import PacketType, SCIONHeader, SCIONPacket
from lib.packet.scion_addr import SCIONAddr, ISD_AD


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
    Domain's ID, the SupportSignatureField, the HopOpaqueField, the
    SupportPCBField, and the revocation tokens for the interfaces
    included in the HOF.
    TODO: this will be used for both top-down and peer links
    """
    LEN = 20 + 2 * 32

    def __init__(self, raw=None):
        Marking.__init__(self)
        self.isd_id = 0
        self.ad_id = 0
        self.ssf = None
        self.hof = None
        self.ig_rev_token = 32 * b"\x00"
        self.eg_rev_token = 32 * b"\x00"
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw[:]
        dlen = len(raw)
        if dlen < PCBMarking.LEN:
            logging.warning("PCBM: Data too short for parsing, len: %u", dlen)
            return
        (self.isd_id, self.ad_id) = ISD_AD.from_raw(raw[:ISD_AD.LEN])
        offset = ISD_AD.LEN
        self.ssf = SupportSignatureField(raw[offset:offset+SupportSignatureField.LEN])
        offset += SupportSignatureField.LEN
        self.hof = HopOpaqueField(raw[offset:offset+HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        self.ig_rev_token = raw[offset:offset+32]
        offset += 32
        self.eg_rev_token = raw[offset:offset+32]
        self.parsed = True

    @classmethod
    def from_values(cls, isd_id=0, ad_id=0, ssf=None, hof=None,
                    ig_rev_token=32 * b"\x00", eg_rev_token=32 * b"\x00"):
        """
        Returns PCBMarking with fields populated from values.

        :param ad_id: Autonomous Domain's ID.
        :param ssf: SupportSignatureField object.
        :param hof: HopOpaqueField object.
        :param ig_rev_token: Revocation token for the ingress if
                             in the HopOpaqueField.
        :param eg_rev_token: Revocation token for the egress if
                             in the HopOpaqueField.
        """
        pcbm = PCBMarking()
        pcbm.isd_id = isd_id
        pcbm.ad_id = ad_id
        pcbm.ssf = ssf
        pcbm.hof = hof
        pcbm.ig_rev_token = ig_rev_token
        pcbm.eg_rev_token = eg_rev_token
        return pcbm

    def pack(self):
        """
        Returns PCBMarking as a binary string.
        """
        return (ISD_AD(self.isd_id, self.ad_id).pack() + self.ssf.pack() +
                self.hof.pack() + self.ig_rev_token + self.eg_rev_token)

    def __str__(self):
        pcbm_str = "[PCB Marking isd,ad (%d, %d)]\n" % (self.isd_id, self.ad_id)
        pcbm_str += "ig_rev_token: %s\neg_rev_token:%s\n" % (self.ig_rev_token,
                                                             self.eg_rev_token)
        pcbm_str += str(self.ssf)
        pcbm_str += str(self.hof) + '\n'
        return pcbm_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.ad_id == other.ad_id and
                    self.ssf == other.ssf and
                    self.hof == other.hof and
                    self.ig_rev_token == other.ig_rev_token and
                    self.eg_rev_token == other.eg_rev_token)
        else:
            return False


class ADMarking(Marking):
    """
    Packs all fields for a specific Autonomous Domain.
    """

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
        self.raw = raw[:]
        dlen = len(raw)
        if dlen < PCBMarking.LEN:
            logging.warning("AD: Data too short for parsing, len: %u", dlen)
            return
        self.pcbm = PCBMarking(raw[:PCBMarking.LEN])
        raw = raw[PCBMarking.LEN:]
        while len(raw) > self.pcbm.ssf.sig_len:
            peer_marking = PCBMarking(raw[:PCBMarking.LEN])
            self.pms.append(peer_marking)
            raw = raw[PCBMarking.LEN:]
        self.sig = raw[:]
        self.parsed = True

    @classmethod
    def from_values(cls, pcbm=None, pms=None, sig=b''):
        """
        Returns ADMarking with fields populated from values.

        @param pcbm: PCBMarking object.
        @param pms: List of PCBMarking objects.
        @param sig: Beacon's signature.
        """
        ad_marking = ADMarking()
        pcbm.ssf.sig_len = len(sig)
        pcbm.ssf.block_size = (1 + len(pms)) * PCBMarking.LEN
        ad_marking.pcbm = pcbm
        ad_marking.pms = (pms if pms is not None else [])
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
        ad_str += ("[Signature: %s]\n" %
                   base64.b64encode(self.sig).decode('utf-8'))
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
    LEN = 16 + 32

    def __init__(self, raw=None):
        Marking.__init__(self)
        self.iof = None
        self.trcf = None
        self.segment_id = 32 * b"\x00"
        self.ads = []
        self.min_exp_time = 2 ** 8 - 1
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.size = len(raw)
        self.raw = raw[:]
        dlen = len(raw)
        if dlen < PathSegment.LEN:
            logging.warning("PathSegment: Data too short for parsing, " +
                            "len: %u", dlen)
            return
        # Populate the info and ROT OFs from the first and second 8-byte blocks
        # of the segment, respectively.
        self.iof = InfoOpaqueField(raw[0:8])
        self.trcf = TRCField(raw[8:16])
        self.segment_id = raw[16:48]
        raw = raw[48:]
        for _ in range(self.iof.hops):
            pcbm = PCBMarking(raw[:PCBMarking.LEN])
            ad_marking = ADMarking(raw[:pcbm.ssf.sig_len + pcbm.ssf.block_size])
            self.add_ad(ad_marking)
            raw = raw[pcbm.ssf.sig_len + pcbm.ssf.block_size:]
        self.parsed = True

    def pack(self):
        """
        Returns PathSegment as a binary string.
        """
        pcb_bytes = self.iof.pack() + self.trcf.pack()
        pcb_bytes += self.segment_id
        for ad_marking in self.ads:
            pcb_bytes += ad_marking.pack()
        return pcb_bytes

    def add_ad(self, ad_marking):
        """
        Appends a new AD block.
        """
        if ad_marking.pcbm.hof.exp_time < self.min_exp_time:
            self.min_exp_time = ad_marking.pcbm.hof.exp_time
        self.ads.append(ad_marking)
        self.iof.hops = len(self.ads)

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
        iof = copy.copy(self.iof)
        if reverse_direction:
            ads = list(reversed(self.ads))
            iof.up_flag = self.iof.up_flag ^ True
        else:
            ads = self.ads
        for ad_marking in ads:
            hofs.append(ad_marking.pcbm.hof)
        core_path = CorePath.from_values(iof, hofs)
        return core_path

    def get_isd(self):
        """
        Returns the ISD ID.
        """
        return self.iof.isd_id

    def get_last_pcbm(self):
        """
        Returns the PCBMarking belonging to the last AD on the path.
        """
        if self.ads:
            return self.ads[-1].pcbm
        else:
            return None

    def get_first_pcbm(self):
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

    def get_hops_hash(self, hex=False):
        """
        Returns the hash over all the interface revocation tokens included in
        the path segment.
        """
        h = SHA256.new()
        for ad in self.ads:
            h.update(ad.pcbm.ig_rev_token)
            h.update(ad.pcbm.eg_rev_token)
            for pm in ad.pms:
                h.update(pm.ig_rev_token)
                h.update(pm.eg_rev_token)
        if hex:
            return h.hexdigest()
        return h.digest()

    def get_n_peer_links(self):
        """
        Return the total number of peer links in the PathSegment.
        """
        n_peer_links = 0
        for ad in self.ads:
            n_peer_links += len(ad.pms)
        return n_peer_links

    def get_n_hops(self):
        """
        Return the number of hops in the PathSegment.
        """
        return len(self.ads)

    def get_timestamp(self):
        """
        Returns the creation timestamp of this PathSegment.
        """
        return self.iof.timestamp

    def set_timestamp(self, timestamp):
        """
        Updates the timestamp in the IOF.
        """
        assert timestamp < 2 ** 32 - 1
        self.iof.timestamp = timestamp

    def get_expiration_time(self):
        """
        Returns the expiration time of the path segment in real time.
        """
        return (self.iof.timestamp + int(self.min_exp_time * EXP_TIME_UNIT))

    def get_all_iftokens(self):
        """
        Returns all interface revocation tokens included in the path segment.
        """
        tokens = []
        for ad in self.ads:
            tokens.append(ad.pcbm.ig_rev_token)
            tokens.append(ad.pcbm.eg_rev_token)
            for pm in ad.pms:
                tokens.append(pm.ig_rev_token)
                tokens.append(pm.eg_rev_token)
        return tokens

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
            pcb.trcf = TRCField(raw[8:16])
            pcb.segment_id = raw[16:48]
            raw = raw[48:]
            for _ in range(pcb.iof.hops):
                pcbm = PCBMarking(raw[:PCBMarking.LEN])
                ad_marking = ADMarking(raw[:pcbm.ssf.sig_len +
                                           pcbm.ssf.block_size])
                pcb.add_ad(ad_marking)
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
        pcb_str += "Segment ID: %s\n" % str(self.segment_id)
        pcb_str += str(self.iof) + "\n" + str(self.trcf) + "\n"
        for ad_marking in self.ads:
            pcb_str += str(ad_marking)
        return pcb_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.iof == other.iof and
                    self.trcf == other.trcf and
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
    def from_values(cls, src_isd_ad, dst, pcb):
        """
        Returns a PathConstructionBeacon packet with the values specified.

        :param src_isd_ad: Source's 'ISD_AD' namedtuple.
        :param dst: Destination address (must be a 'SCIONAddr' object)
        :param pcb: Path Construction Beacon ('PathSegment' class)
        """
        beacon = PathConstructionBeacon()
        beacon.pcb = pcb
        src = SCIONAddr.from_values(src_isd_ad.isd, src_isd_ad.ad,
                                    PacketType.BEACON)
        beacon.hdr = SCIONHeader.from_values(src, dst)
        return beacon

    def pack(self):
        self.payload = self.pcb.pack()
        return SCIONPacket.pack(self)
