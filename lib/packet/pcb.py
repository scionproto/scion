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
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.path import CorePath
from lib.packet.scion import PacketType, SCIONHeader, SCIONPacket
from lib.packet.scion_addr import SCIONAddr, ISD_AD

#: Default value for length (in bytes) of a revocation token.
REV_TOKEN_LEN = 32


class Marking(object):
    """
    Base class for all marking objects.
    """
    def __init__(self):
        """
        Initialize an instance of the class Marking.
        """
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
    Pack all fields for a specific PCB marking, which include: ISD and AD
    numbers, the HopOpaqueField, and the revocation token for the ingress
    interfaces included in the HOF. (Revocation token for egress interface is
    included within ADMarking.)
    """
    LEN = 12 + REV_TOKEN_LEN

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PCBMarking.

        :param raw:
        :type raw:
        """
        Marking.__init__(self)
        self.isd_id = 0
        self.ad_id = 0
        self.hof = None
        self.ig_rev_token = REV_TOKEN_LEN * b"\x00"
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
        self.hof = HopOpaqueField(raw[offset:offset + HopOpaqueField.LEN])
        offset += HopOpaqueField.LEN
        self.ig_rev_token = raw[offset:offset + REV_TOKEN_LEN]
        self.parsed = True

    @classmethod
    def from_values(cls, isd_id, ad_id, hof,
                    ig_rev_token=REV_TOKEN_LEN * b"\x00"):
        """
        Returns PCBMarking with fields populated from values.

        :param ad_id: Autonomous Domain's ID.
        :param hof: HopOpaqueField object.
        :param ig_rev_token: Revocation token for the ingress if
                             in the HopOpaqueField.
        """
        pcbm = PCBMarking()
        pcbm.isd_id = isd_id
        pcbm.ad_id = ad_id
        pcbm.hof = hof
        pcbm.ig_rev_token = ig_rev_token
        return pcbm

    def pack(self):
        """
        Returns PCBMarking as a binary string.
        """
        return (ISD_AD(self.isd_id, self.ad_id).pack() + self.hof.pack() +
                self.ig_rev_token)

    def __str__(self):
        pcbm_str = "[PCB Marking isd,ad (%d, %d)]\n" % (self.isd_id, self.ad_id)
        pcbm_str += "ig_rev_token: %s\n" % self.ig_rev_token
        pcbm_str += str(self.hof) + '\n'
        return pcbm_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.isd_id == other.isd_id and
                    self.ad_id == other.ad_id and
                    self.hof == other.hof and
                    self.ig_rev_token == other.ig_rev_token)
        else:
            return False


class ADMarking(Marking):
    """
    Packs all fields for a specific Autonomous Domain.
    """
    # Length of a first row (containg cert version, and lengths of signature,
    # ASD, and block) of ADMarking
    METADATA_LEN = 8

    def __init__(self, raw=None):
        """
        Initialize an instance of the class ADMarking.

        :param raw:
        :type raw:
        """
        Marking.__init__(self)
        self.pcbm = None
        self.pms = []
        self.sig = b''
        self.asd = b''
        self.eg_rev_token = REV_TOKEN_LEN * b"\x00"
        self.cert_ver = 0
        self.sig_len = 0
        self.asd_len = 0
        self.block_len = 0
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw[:]
        dlen = len(raw)
        if dlen < PCBMarking.LEN + self.METADATA_LEN + REV_TOKEN_LEN:
            logging.warning("AD: Data too short for parsing, len: %u", dlen)
            return
        self._parse_metadata(raw[:self.METADATA_LEN])
        raw = raw[self.METADATA_LEN:]
        self._parse_pcbm(raw[:PCBMarking.LEN])
        raw = raw[PCBMarking.LEN:]
        offset = self._parse_peers(raw)
        raw = raw[offset:]
        self.asd = raw[:self.asd_len]
        raw = raw[self.asd_len:]
        self.eg_rev_token = raw[:REV_TOKEN_LEN]
        self.sig = raw[REV_TOKEN_LEN:]
        self.parsed = True

    def _parse_metadata(self, raw):
        """
        Populates metadata fields from a raw bytes block.

        :param raw:
        :return:
        """
        assert len(raw) == self.METADATA_LEN
        (self.cert_ver, self.sig_len, self.asd_len, self.block_len) = \
            struct.unpack("!HHHH", raw)

    def _parse_pcbm(self, raw):
        """
        Populates PCBMarking field from a raw bytes block.

        :param raw:
        :return:
        """
        assert len(raw) == PCBMarking.LEN
        self.pcbm = PCBMarking(raw)

    def _parse_peers(self, raw):
        """
        Populated Peer Marking fields from a raw bytes block

        :param raw:
        :return:
        """
        offset = 0
        while len(raw) > self.sig_len + self.asd_len + REV_TOKEN_LEN:
            peer_marking = PCBMarking(raw[:PCBMarking.LEN])
            self.pms.append(peer_marking)
            raw = raw[PCBMarking.LEN:]
            offset += PCBMarking.LEN
        return offset

    @classmethod
    def from_values(cls, pcbm=None, pms=None,
                    eg_rev_token=REV_TOKEN_LEN * b"\x00", sig=b'', asd=b''):
        """
        Returns ADMarking with fields populated from values.

        :param pcbm: PCBMarking object.
        :param pms: List of PCBMarking objects.
        :param eg_rev_token: Revocation token for the egress if
                             in the HopOpaqueField.
        :param sig: Beacon's signature.
        :param asd: Additional Signed Data appended to the beacon.
        """
        ad_marking = ADMarking()
        ad_marking.pcbm = pcbm
        ad_marking.pms = (pms if pms is not None else [])
        ad_marking.block_len = (1 + len(ad_marking.pms)) * PCBMarking.LEN
        ad_marking.sig = sig
        ad_marking.sig_len = len(sig)
        ad_marking.asd = asd
        ad_marking.asd_len = len(asd)
        ad_marking.eg_rev_token = eg_rev_token
        return ad_marking

    def pack(self):
        """
        Returns ADMarking as a binary string.
        """
        ad_bytes = struct.pack("!HHHH", self.cert_ver, self.sig_len,
                               self.asd_len, self.block_len)
        ad_bytes += self.pcbm.pack()
        for peer_marking in self.pms:
            ad_bytes += peer_marking.pack()
        ad_bytes += self.asd
        ad_bytes += self.eg_rev_token
        ad_bytes += self.sig
        return ad_bytes

    def remove_signature(self):
        """
        Removes the signature from the AD block.
        """
        self.sig = b''
        self.sig_len = 0

    def remove_asd(self):
        """
        Removes the Additional Signed Data (ASD) from the AD block.
        Note that after ASD is removed, a corresponding signature is invalid.
        """
        self.asd = b''
        self.asd_len = 0

    def __str__(self):
        ad_str = "[Autonomous Domain]\n"
        ad_str += ("cert_ver: %d, asd_len %d, sig_len: %d, block_len: %d\n" %
                   (self.cert_ver, self.asd_len, self.sig_len, self.block_len))
        ad_str += str(self.pcbm)
        for peer_marking in self.pms:
            ad_str += str(peer_marking)
        ad_str += ("[ASD: %s]\n" % self.asd)
        ad_str += ("[eg_rev_token: %s]\n" % self.eg_rev_token)
        ad_str += ("[Signature: %s]\n" %
                   base64.b64encode(self.sig).decode('utf-8'))
        return ad_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.pcbm == other.pcbm and
                    self.pms == other.pms and
                    self.asd == other.asd and
                    self.eg_rev_token == other.eg_rev_token and
                    self.sig == other.sig)
        else:
            return False


class PathSegment(Marking):
    """
    Packs all PathSegment fields for a specific beacon.
    """
    MIN_LEN = 14 + REV_TOKEN_LEN

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathSegment.

        :param raw:
        :type raw:
        """
        Marking.__init__(self)
        self.iof = None
        self.trc_ver = 0
        self.if_id = 0
        self.segment_id = REV_TOKEN_LEN * b"\x00"
        self.ads = []
        self.min_exp_time = 2 ** 8 - 1
        if raw is not None:
            self.parse(raw)

    def parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        assert isinstance(raw, bytes)
        self.raw = raw[:]
        dlen = len(raw)
        if dlen < PathSegment.MIN_LEN:
            logging.warning("PathSegment: Data too short for parsing, " +
                            "len: %u", dlen)
            return
        # Populate the info and ROT OFs from the first and second 8-byte blocks
        # of the segment, respectively.
        self.iof = InfoOpaqueField(raw[:InfoOpaqueField.LEN])
        offset = InfoOpaqueField.LEN
        self.trc_ver, self.if_id = struct.unpack("!IH", raw[offset:offset + 6])
        offset += 6  # 4B for trc_ver and 2B for if_id.
        self.segment_id = raw[offset:offset + REV_TOKEN_LEN]
        offset += REV_TOKEN_LEN
        raw = raw[offset:]
        offset += self._parse_hops(raw)
        self.parsed = True
        return offset

    def _parse_hops(self, raw):
        """
        Populates AD Hops from a raw bytes block.
        """
        offset = 0
        for _ in range(self.iof.hops):
            (_, asd_len, sig_len, block_len) = \
                struct.unpack("!HHHH", raw[:ADMarking.METADATA_LEN])
            ad_len = (sig_len + asd_len + block_len +
                      ADMarking.METADATA_LEN + REV_TOKEN_LEN)
            ad_marking = ADMarking(raw[:ad_len])
            self.add_ad(ad_marking)
            raw = raw[ad_len:]
            offset += ad_len
        return offset

    def pack(self):
        """
        Returns PathSegment as a binary string.
        """
        pcb_bytes = self.iof.pack()
        pcb_bytes += struct.pack("!IH", self.trc_ver, self.if_id)
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

    def remove_asds(self):
        """
        Removes the Additional Signed Data (ASD) from each AD block.
        Note that after ASD is removed, a corresponding signature is invalid.
        """
        for ad_marking in self.ads:
            ad_marking.remove_asd()

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

    def get_last_adm(self):
        """
        Returns the last ADMarking on the path.
        """
        if self.ads:
            return self.ads[-1]
        else:
            return None

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
            h.update(ad.eg_rev_token)
            for pm in ad.pms:
                h.update(pm.ig_rev_token)
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
        return self.iof.timestamp + int(self.min_exp_time * EXP_TIME_UNIT)

    def get_all_iftokens(self):
        """
        Returns all interface revocation tokens included in the path segment.
        """
        tokens = []
        for ad in self.ads:
            tokens.append(ad.pcbm.ig_rev_token)
            tokens.append(ad.eg_rev_token)
            for pm in ad.pms:
                tokens.append(pm.ig_rev_token)
        return tokens

    @staticmethod
    def deserialize(raw):
        """
        Deserializes a bytes string into a list of PathSegments.
        """
        assert isinstance(raw, bytes)
        dlen = len(raw)
        if dlen < PathSegment.MIN_LEN:
            logging.warning("HPB: Data too short for parsing, len: %u", dlen)
            return
        pcbs = []
        while len(raw) > 0:
            pcb = PathSegment()
            offset = pcb.parse(raw)
            pcbs.append(pcb)
            raw = raw[offset:]
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
        pcb_str += str(self.iof) + "\n"
        pcb_str += "trc_ver: %d, if_id: %d\n" % (self.trc_ver, self.if_id)
        for ad_marking in self.ads:
            pcb_str += str(ad_marking)
        return pcb_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.iof == other.iof and
                    self.trc_ver == other.trc_ver and
                    self.segment_id == other.segment_id and
                    self.ads == other.ads)
        else:
            return False


class PathConstructionBeacon(SCIONPacket):
    """
    PathConstructionBeacon packet, used for path propagation.
    """
    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathConstructionBeacon.

        :param raw:
        :type raw:
        """
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
