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
import struct
from abc import ABCMeta, abstractmethod
from datetime import datetime

# External packages
from Crypto.Hash import SHA256

# SCION
from lib.defines import EXP_TIME_UNIT
from lib.errors import SCIONParseError
from lib.packet.ext.pcb_ext import MTUExtension
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.packet_base import PayloadClass, SCIONPayloadBase
from lib.packet.path import CorePath
from lib.packet.scion_addr import ISD_AD
from lib.util import Raw

#: Default value for length (in bytes) of a revocation token.
REV_TOKEN_LEN = 32

# Dictionary of supported extensions
PCB_EXTENSION_MAP = {
    (MTUExtension.EXT_TYPE): MTUExtension,
}


class PCBType(object):
    SEGMENT = 0


class MarkingBase(object, metaclass=ABCMeta):
    """
    Base class for all marking objects.
    """
    @abstractmethod
    def _parse(self):
        raise NotImplementedError

    @abstractmethod
    def from_values(self):
        raise NotImplementedError

    @abstractmethod
    def pack(self):
        raise NotImplementedError


class PCBMarking(MarkingBase):
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
        super().__init__()
        self.isd_id = 0
        self.ad_id = 0
        self.hof = None
        self.ig_rev_token = bytes(REV_TOKEN_LEN)
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, "PCBMarking", self.LEN)
        self.isd_id, self.ad_id = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.hof = HopOpaqueField(data.pop(HopOpaqueField.LEN))
        self.ig_rev_token = data.pop(REV_TOKEN_LEN)

    @classmethod
    def from_values(cls, isd_id, ad_id, hof, ig_rev_token=None):
        """
        Returns PCBMarking with fields populated from values.

        :param ad_id: Autonomous Domain's ID.
        :param hof: HopOpaqueField object.
        :param ig_rev_token: Revocation token for the ingress if
                             in the HopOpaqueField.
        """
        inst = PCBMarking()
        inst.isd_id = isd_id
        inst.ad_id = ad_id
        inst.hof = hof
        inst.ig_rev_token = ig_rev_token or bytes(REV_TOKEN_LEN)
        return inst

    def pack(self):
        packed = []
        packed.append(ISD_AD(self.isd_id, self.ad_id).pack())
        packed.append(self.hof.pack())
        packed.append(self.ig_rev_token)
        raw = b"".join(packed)
        assert len(raw) == len(self)
        return raw

    def __len__(self):
        return self.LEN

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


class ADMarking(MarkingBase):
    """
    Packs all fields for a specific Autonomous Domain.
    """
    # Length of a first row (containg cert version, and lengths of signature,
    # extensions, and block) of ADMarking
    METADATA_LEN = 8
    MIN_LEN = METADATA_LEN + PCBMarking.LEN + REV_TOKEN_LEN

    def __init__(self, raw=None):
        """
        Initialize an instance of the class ADMarking.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.pcbm = None
        self.pms = []
        self.sig = b''
        self.ext = []
        self.eg_rev_token = bytes(REV_TOKEN_LEN)
        self.cert_ver = 0
        self.sig_len = 0
        self.ext_len = 0
        self.block_len = 0
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, "ADMarking", self.MIN_LEN, min_=True)
        self.cert_ver, self.sig_len, self.ext_len, self.block_len = \
            struct.unpack("!HHHH", data.pop(self.METADATA_LEN))
        self.pcbm = PCBMarking(data.pop(PCBMarking.LEN))
        self._parse_peers(data)
        self._parse_ext(data)
        self.eg_rev_token = data.pop(REV_TOKEN_LEN)
        self.sig = data.pop()

    def _parse_peers(self, data):
        """
        Populated Peer Marking fields from raw bytes

        :param data:
        :type data: :class:`lib.util.Raw`
        """
        while len(data) > self.sig_len + self.ext_len + REV_TOKEN_LEN:
            self.pms.append(PCBMarking(data.pop(PCBMarking.LEN)))

    def _parse_ext(self, data):
        """
        """
        while len(data) > self.sig_len + REV_TOKEN_LEN:
            ext_type = data.pop(1)
            ext_len = data.pop(1)
            constr = PCB_EXTENSION_MAP[ext_type]
            self.ext.append(constr(data.pop(ext_len)))

    def _pack_ext(self):
        packed = []
        for ext in self.ext:
            ext_type = struct.pack("!B", ext.EXT_TYPE)
            packed.append(ext_type)
            ext_len = struct.pack("!B", len(ext))
            packed.append(ext_len)
            packed.append(ext.pack())
        return b"".join(packed)

    @classmethod
    def from_values(cls, pcbm=None, pms=None,
                    eg_rev_token=None, sig=b'', ext=None):
        """
        Returns ADMarking with fields populated from values.

        :param pcbm: PCBMarking object.
        :param pms: List of PCBMarking objects.
        :param eg_rev_token: Revocation token for the egress if
                             in the HopOpaqueField.
        :param sig: Beacon's signature.
        """
        inst = ADMarking()
        inst.pcbm = pcbm
        inst.pms = pms or []
        inst.block_len = (1 + len(inst.pms)) * PCBMarking.LEN
        inst.sig = sig
        inst.sig_len = len(sig)
        if ext:
            inst.ext = ext
        inst.ext_len = len(inst._pack_ext())
        inst.eg_rev_token = eg_rev_token or bytes(REV_TOKEN_LEN)
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!HHHH", self.cert_ver, self.sig_len,
                                  self.ext_len, self.block_len))
        packed.append(self.pcbm.pack())
        for peer_marking in self.pms:
            packed.append(peer_marking.pack())
        packed.append(self._pack_ext())
        packed.append(self.eg_rev_token)
        packed.append(self.sig)
        raw = b"".join(packed)
        assert len(raw) == len(self)
        return raw

    def remove_signature(self):
        """
        Removes the signature from the AD block.
        """
        self.sig = b''
        self.sig_len = 0

    def remove_ext(self):
        """
        """
        self.ext = []
        self.ext_len = 0

    def add_ext(self, ext):
        """
        """
        self.ext.append(ext)
        self.ext_len += len(ext) + 2  # Add extensions header.

    def __len__(self):
        ext_len = len(self._pack_ext())
        return (
            self.MIN_LEN + len(self.pms) * PCBMarking.LEN + len(self.sig) +
            ext_len
        )

    def __str__(self):
        ad_str = "[Autonomous Domain]\n"
        ad_str += ("cert_ver: %d, ext_len %d, sig_len: %d, block_len: %d\n" %
                   (self.cert_ver, self.ext_len, self.sig_len, self.block_len))
        ad_str += str(self.pcbm)
        for peer_marking in self.pms:
            ad_str += str(peer_marking)
        for ext in self.ext:
            ad_str += "%s\n" % str(ext)
        ad_str += ("[eg_rev_token: %s]\n" % self.eg_rev_token)
        ad_str += ("[Signature: %s]\n" %
                   base64.b64encode(self.sig).decode('utf-8'))
        return ad_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.pcbm == other.pcbm and
                    self.pms == other.pms and
                    self.ext == other.ext and
                    self.eg_rev_token == other.eg_rev_token and
                    self.sig == other.sig)
        else:
            return False


class PathSegment(SCIONPayloadBase):
    """
    Packs all PathSegment fields for a specific beacon.

    :cvar MIN_LEN: the minimum length of a PathSegment in bytes.
    :type MIN_LEN: int

    :ivar iof: the info opaque field of the segment.
    :type iof: :class:`InfoOpaqueField`
    :ivar trc_ver: the TRC version number at the creating AS.
    :type trc_ver: int
    :ivar if_id: the interface identifier.
    :type if_id: int
    :ivar ads: the ADs on the path.
    :type ads: list
    """
    PAYLOAD_CLASS = PayloadClass.PCB
    PAYLOAD_TYPE = PCBType.SEGMENT
    MIN_LEN = InfoOpaqueField.LEN + 4 + 2
    NAME = "PathSegment"

    def __init__(self, raw=None):
        """
        Initialize an instance of the class PathSegment.

        :param raw:
        :type raw:
        """
        super().__init__()
        self.iof = None
        self.trc_ver = 0
        self.if_id = 0
        self.ads = []
        self.min_exp_time = 2 ** 8 - 1  # TODO: eliminate 8 as magic number
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self.iof = InfoOpaqueField(data.pop(InfoOpaqueField.LEN))
        # 4B for trc_ver and 2B for if_id.
        self.trc_ver, self.if_id = struct.unpack("!IH", data.pop(6))
        self._parse_hops(data)
        return data.offset()

    def _parse_hops(self, data):
        """
        Populates AD Hops from raw bytes.

        :param data:
        :type data: :class:`lib.util.Raw`
        """
        for _ in range(self.iof.hops):
            (_, ext_len, sig_len, block_len) = \
                struct.unpack("!HHHH", data.get(ADMarking.METADATA_LEN))
            ad_len = (ext_len + sig_len + block_len +
                      ADMarking.METADATA_LEN + REV_TOKEN_LEN)
            self.add_ad(ADMarking(data.pop(ad_len)))

    @classmethod
    def from_values(cls, iof):
        inst = cls()
        inst.iof = iof
        return inst

    def pack(self):
        packed = []
        packed.append(self.iof.pack())
        packed.append(struct.pack("!IH", self.trc_ver, self.if_id))
        for ad_marking in self.ads:
            packed.append(ad_marking.pack())
        return b"".join(packed)

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

    def remove_all_ext(self):
        """
        Removes extensions from each AD block.  Note that after an extensions is
        removed, a corresponding signature is invalid.
        """
        for ad_marking in self.ads:
            ad_marking.remove_ext()

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
        data = Raw(raw, "PathSegment")
        pcbs = []
        while len(data):
            pcb = PathSegment(data.get())
            data.pop(len(pcb))
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

    def __len__(self):
        l = self.MIN_LEN
        for ad in self.ads:
            l += len(ad)
        return l

    def short_desc(self):
        """
        Return a short description string of the PathSegment, consisting of a
        truncated hash, the IOF timestamp, and the list of hops.
        """
        desc = []
        dt = datetime.fromtimestamp(self.get_timestamp())
        desc.append("%s, %s, " % (
            self.get_hops_hash(hex=True)[:12],
            dt.isoformat(),
        ))
        hops = []
        for adm in self.ads:
            hops.append("(%d, %d)" % (adm.pcbm.isd_id, adm.pcbm.ad_id))
        desc.append("->".join(hops))
        return "".join(desc)

    def __str__(self):
        pcb_str = "[PathSegment]\n"
        pcb_str += str(self.iof) + "\n"
        pcb_str += "trc_ver: %d, if_id: %d\n" % (self.trc_ver, self.if_id)
        for ad_marking in self.ads:
            pcb_str += str(ad_marking)
        return pcb_str

    def __eq__(self, other):
        if type(other) is type(self):
            return (self.iof == other.iof and
                    self.trc_ver == other.trc_ver and
                    self.ads == other.ads)
        else:
            return False


def parse_pcb_payload(type_, data):
    type_map = {
        PCBType.SEGMENT: PathSegment,
    }
    if type_ not in type_map:
        raise SCIONParseError("Unsupported pcb type: %s", type_)
    handler = type_map[type_]
    return handler(data.pop())
