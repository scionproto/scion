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
import copy
import logging
import struct

# External packages
from Crypto.Hash import SHA256

# SCION
from lib.crypto.certificate import CertificateChain
from lib.defines import EXP_TIME_UNIT
from lib.errors import SCIONParseError
from lib.flagtypes import PathSegFlags as PSF
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.packet_base import Serializable, SCIONPayloadBase
from lib.packet.path import SCIONPath, min_mtu
from lib.packet.pcb_ext.mtu import MtuPcbExt
from lib.packet.pcb_ext.rev import RevPcbExt
from lib.packet.pcb_ext.sibra import SibraPcbExt
from lib.packet.scion_addr import ISD_AS
from lib.sibra.pcb_ext.info import SibraSegInfo
from lib.sibra.pcb_ext.sof import SibraSegSOF
from lib.types import PayloadClass, PCBType
from lib.util import Raw, hex_str, iso_timestamp

#: Default value for length (in bytes) of a revocation token.
REV_TOKEN_LEN = 32

# Dictionary of supported extensions
PCB_EXTENSION_MAP = {
    (MtuPcbExt.EXT_TYPE): MtuPcbExt,
    (RevPcbExt.EXT_TYPE): RevPcbExt,
    (SibraPcbExt.EXT_TYPE): SibraPcbExt,
    (SibraSegInfo.EXT_TYPE): SibraSegInfo,
    (SibraSegSOF.EXT_TYPE): SibraSegSOF,
}


class PCBMarking(Serializable):
    """
    Pack all fields for a specific PCB marking, which include: ISD and AS
    numbers, the HopOpaqueField, and the revocation token for the ingress
    interfaces included in the HOF. (Revocation token for egress interface is
    included within ASMarking.)
    """
    NAME = "PCBMarking"
    LEN = 12 + REV_TOKEN_LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.isd_as = None
        self.hof = None
        self.ig_rev_token = bytes(REV_TOKEN_LEN)
        super().__init__(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, self.LEN)
        self.isd_as = ISD_AS(data.pop(ISD_AS.LEN))
        self.hof = HopOpaqueField(data.pop(HopOpaqueField.LEN))
        self.ig_rev_token = data.pop(REV_TOKEN_LEN)

    @classmethod
    def from_values(cls, isd_as, hof, ig_rev_token=None):  # pragma: no cover
        """
        Returns PCBMarking with fields populated from values.

        :param isd_as: ISD_AS object.
        :param hof: HopOpaqueField object.
        :param ig_rev_token: Revocation token for the ingress if
                             in the HopOpaqueField.
        """
        inst = PCBMarking()
        inst.isd_as = isd_as
        inst.hof = hof
        inst.ig_rev_token = ig_rev_token or bytes(REV_TOKEN_LEN)
        return inst

    def pack(self):
        packed = []
        packed.append(self.isd_as.pack())
        packed.append(self.hof.pack())
        packed.append(self.ig_rev_token)
        raw = b"".join(packed)
        assert len(raw) == len(self)
        return raw

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __eq__(self, other):  # pragma: no cover
        if type(other) is not type(self):
            return False
        return (self.isd_as == other.isd_as and
                self.hof == other.hof and
                self.ig_rev_token == other.ig_rev_token)

    def __str__(self):
        s = []
        s.append("%s(%dB): ISD-AS %s:" % (self.NAME, len(self), self.isd_as))
        s.append("  ig_rev_token: %s" % hex_str(self.ig_rev_token))
        s.append("  %s" % self.hof)
        return "\n".join(s)


class ASMarking(Serializable):
    """
    Packs all fields for a specific Autonomous System.
    """
    # Length of a first row (containg cert version, and lengths of signature,
    # extensions, and block) of ASMarking
    NAME = "ASMarking"
    METADATA_LEN = 10
    MIN_LEN = METADATA_LEN + PCBMarking.LEN + REV_TOKEN_LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.pcbm = None
        self.pms = []
        self.cert = None
        self.sig = b''
        self.ext = []
        self.eg_rev_token = bytes(REV_TOKEN_LEN)
        self.trc_ver = 0
        self.block_len = 0
        super().__init__(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self.trc_ver, cert_len, sig_len, exts_len, self.block_len = \
            struct.unpack("!HHHHH", data.pop(self.METADATA_LEN))
        self.pcbm = PCBMarking(data.pop(PCBMarking.LEN))
        self._parse_peers(data, cert_len + sig_len, exts_len)
        self._parse_ext(data, cert_len + sig_len)
        self.eg_rev_token = data.pop(REV_TOKEN_LEN)
        self.cert = CertificateChain(data.pop(cert_len).decode('utf-8'))
        self.sig = data.pop()

    def _parse_peers(self, data, cert_sig_len, exts_len):
        """
        Populated Peer Marking fields from raw bytes
        """
        while len(data) > cert_sig_len + exts_len + REV_TOKEN_LEN:
            self.pms.append(PCBMarking(data.pop(PCBMarking.LEN)))

    def _parse_ext(self, data, cert_sig_len):
        while len(data) > cert_sig_len + REV_TOKEN_LEN:
            ext_type = data.pop(1)
            ext_len = data.pop(1)
            constr = PCB_EXTENSION_MAP.get(ext_type)
            ext_data = data.pop(ext_len)
            if not constr:
                logging.warning("Unknown extension type: %d", ext_type)
                continue
            self.ext.append(constr(ext_data))

    @classmethod
    def from_values(cls, pcbm=None, pms=None,
                    eg_rev_token=None, cert=None, sig=b'', ext=None):
        """
        Returns ASMarking with fields populated from values.

        :param pcbm: PCBMarking object.
        :param pms: List of PCBMarking objects.
        :param eg_rev_token: Revocation token for the egress if
                             in the HopOpaqueField.
        :param sig: Beacon's signature.
        """
        inst = ASMarking()
        inst.pcbm = pcbm
        inst.pms = pms or []
        inst.block_len = (1 + len(inst.pms)) * PCBMarking.LEN
        inst.cert = cert
        inst.sig = sig
        inst.ext = ext or []
        inst.eg_rev_token = eg_rev_token or bytes(REV_TOKEN_LEN)
        return inst

    def pack(self):
        packed = []
        packed_ext = self._pack_ext()
        packed.append(struct.pack("!HHHHH", self.trc_ver, len(self.cert),
                                  len(self.sig), len(packed_ext),
                                  self.block_len))
        packed.append(self.pcbm.pack())
        for peer_marking in self.pms:
            packed.append(peer_marking.pack())
        packed.append(packed_ext)
        packed.append(self.eg_rev_token)
        packed.append(self.cert.pack())
        packed.append(self.sig)
        raw = b"".join(packed)
        assert len(raw) == len(self)
        return raw

    def _pack_ext(self):
        packed = []
        for ext in self.ext:
            packed.append(struct.pack("!B", ext.EXT_TYPE))
            packed.append(struct.pack("!B", len(ext)))
            packed.append(ext.pack())
        return b"".join(packed)

    def _remove_signature(self):  # pragma: no cover
        """
        Removes the signature from the AS block.
        """
        self.sig = b''

    def _remove_cert(self):  # pragma: no cover
        """
        Removes the certificate from the AS block.
        """
        self.cert = CertificateChain()

    def add_ext(self, ext):  # pragma: no cover
        """
        Add beacon extension.
        """
        self.ext.append(ext)

    def find_ext(self, type_):  # pragma: no cover
        for ext in self.ext:
            if ext.EXT_TYPE == type_:
                return ext

    def __len__(self):  # pragma: no cover
        return (
            self.MIN_LEN + len(self.pms) * PCBMarking.LEN + len(self.cert) +
            len(self.sig) + len(self._pack_ext())
        )

    def __eq__(self, other):  # pragma: no cover
        if type(other) is not type(self):
            return False
        return (self.pcbm == other.pcbm and
                self.pms == other.pms and
                self.ext == other.ext and
                self.eg_rev_token == other.eg_rev_token and
                self.cert == other.cert and
                self.sig == other.sig)

    def __str__(self):
        s = []
        s.append("%s(%sB):" % (self.NAME, len(self)))
        s.append("  trc_ver: %s, ext_len %s, sig_len: %s, block_len: %s" %
                 (self.trc_ver, len(self._pack_ext()),
                  len(self.sig), self.block_len))
        for line in str(self.pcbm).splitlines():
            s.append("  %s" % line)
        if self.pms:
            s.append("  Peer markings:")
        for pm in self.pms:
            for line in str(pm).splitlines():
                s.append("    %s" % line)
        if self.ext:
            s.append("  PCB Extensions:")
        for ext in self.ext:
            s.append("    %s" % str(ext))
        s.append("  eg_rev_token: %s" % hex_str(self.eg_rev_token))
        s.append("  Certificate: %s" % self.cert)
        s.append("  Signature: %s" % hex_str(self.sig))
        return "\n".join(s)


class PathSegment(SCIONPayloadBase):
    """
    Packs all PathSegment fields for a specific beacon.

    :cvar int MIN_LEN: the minimum length of a PathSegment in bytes.

    :ivar iof: the info opaque field of the segment.
    :type iof: :class:`InfoOpaqueField`
    :ivar int trc_ver: the TRC version number at the creating AS.
    :ivar int if_id: the interface identifier.
    :ivar list ases: the ASes on the path.
    """
    NAME = "PathSegment"
    PAYLOAD_CLASS = PayloadClass.PCB
    PAYLOAD_TYPE = PCBType.SEGMENT
    MIN_LEN = InfoOpaqueField.LEN + 4 + 2 + 1

    def __init__(self, raw=None):  # pragma: no cover
        self.iof = None
        self.trc_ver = 0  # FIXME(PSz): drop this field.
        self.if_id = 0
        self.flags = 0
        self.ases = []
        self.min_exp_time = 2 ** 8 - 1  # TODO: eliminate 8 as magic number
        self.mtu = None
        super().__init__(raw)

    def _parse(self, raw):
        """
        Populates fields from a raw bytes block.
        """
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self.iof = InfoOpaqueField(data.pop(InfoOpaqueField.LEN))
        # 4B for trc_ver, 2B for if_id, 1B for flags.
        self.trc_ver, self.if_id, self.flags = struct.unpack(
            "!IHB", data.pop(7))
        self._parse_hops(data)
        self._set_mtu()
        return data.offset()

    def is_sibra(self):  # pragma: no cover
        return bool(self.flags & PSF.SIBRA)

    def _parse_hops(self, data):
        for _ in range(self.iof.hops):
            (_, exts_len, cert_len, sig_len, block_len) = \
                struct.unpack("!HHHHH", data.get(ASMarking.METADATA_LEN))
            as_len = (exts_len + cert_len + sig_len + block_len +
                      ASMarking.METADATA_LEN + REV_TOKEN_LEN)
            self.add_as(ASMarking(data.pop(as_len)))

    @classmethod
    def from_values(cls, iof, flags=0):  # pragma: no cover
        inst = cls()
        inst.iof = iof
        inst.flags = flags
        return inst

    def pack(self):
        self._set_mtu()
        packed = []
        packed.append(self.iof.pack())
        packed.append(struct.pack("!IHB", self.trc_ver, self.if_id, self.flags))
        for asm in self.ases:
            packed.append(asm.pack())
        return b"".join(packed)

    def _set_mtu(self):  # pragma: no cover
        self.mtu = None
        for asm in self.ases:
            for ext in asm.ext:
                if ext.EXT_TYPE == MtuPcbExt.EXT_TYPE:
                    self.mtu = min_mtu(self.mtu, ext.mtu)

    def add_as(self, asm):
        """
        Appends a new ASMarking block.
        """
        if asm.pcbm.hof.exp_time < self.min_exp_time:
            self.min_exp_time = asm.pcbm.hof.exp_time
        self.ases.append(asm)
        self.iof.hops = len(self.ases)
        self._set_mtu()

    def _remove_signatures(self):  # pragma: no cover
        """
        Removes the signatures from each AS block.
        """
        for asm in self.ases:
            asm._remove_signature()

    def _remove_certs(self):  # pragma: no cover
        """
        Removes the certificates from each AS block.
        """
        for asm in self.ases:
            asm._remove_cert()

    def remove_crypto(self):  # pragma: no cover
        """
        Remover the signatures and certificates from each AS block.
        """
        self._remove_signatures()
        self._remove_certs()

    def get_path(self, reverse_direction=False):
        """
        Returns the list of HopOpaqueFields in the path.
        """
        hofs = []
        iof = copy.copy(self.iof)
        ases = self.ases
        if reverse_direction:
            ases = reversed(ases)
            iof.up_flag = self.iof.up_flag ^ True
        for asm in ases:
            hofs.append(asm.pcbm.hof)
        return SCIONPath.from_values(iof, hofs)

    def get_isd(self):  # pragma: no cover
        """
        Returns the ISD ID.
        """
        return self.iof.isd

    def get_last_asm(self):  # pragma: no cover
        """
        Returns the last ASMarking on the path.
        """
        if self.ases:
            return self.ases[-1]
        return None

    def get_last_pcbm(self):  # pragma: no cover
        """
        Returns the PCBMarking belonging to the last AS on the path.
        """
        if self.ases:
            return self.ases[-1].pcbm
        return None

    def get_first_pcbm(self):  # pragma: no cover
        """
        Returns the PCBMarking belonging to the first AS on the path.
        """
        if self.ases:
            return self.ases[0].pcbm
        return None

    def compare_hops(self, other):  # pragma: no cover
        """
        Compares the (AS-level) hops of two half-paths. Returns true if all hops
        are identical and false otherwise.
        """
        if not isinstance(other, PathSegment):
            return False
        self_hops = [asm.pcbm.isd_as for asm in self.ases]
        other_hops = [asm.pcbm.isd_as for asm in other.ases]
        return self_hops == other_hops

    def get_hops_hash(self, hex=False):
        """
        Returns the hash over all the interface revocation tokens included in
        the path segment.
        """
        h = SHA256.new()
        for asm in self.ases:
            h.update(asm.pcbm.ig_rev_token)
            h.update(asm.eg_rev_token)
            for pm in asm.pms:
                h.update(pm.ig_rev_token)
        if hex:
            return h.hexdigest()
        return h.digest()

    def get_n_peer_links(self):  # pragma: no cover
        """
        Return the total number of peer links in the PathSegment.
        """
        n_peer_links = 0
        for asm in self.ases:
            n_peer_links += len(asm.pms)
        return n_peer_links

    def get_n_hops(self):  # pragma: no cover
        """
        Return the number of hops in the PathSegment.
        """
        return len(self.ases)

    def get_timestamp(self):  # pragma: no cover
        """
        Returns the creation timestamp of this PathSegment.
        """
        return self.iof.timestamp

    def set_timestamp(self, timestamp):  # pragma: no cover
        """
        Updates the timestamp in the IOF.
        """
        assert timestamp < 2 ** 32 - 1
        self.iof.timestamp = timestamp

    def get_expiration_time(self):
        """
        Returns the expiration time of the path segment in real time. If a PCB
        extension in the last ASMarking supplies an expiration time, use that.
        Otherwise fall-back to the standard expiration time calculation.
        """
        if self.ases:
            for ext in self.ases[-1].ext:
                exp_ts = ext.exp_ts()
                if exp_ts is not None:
                    return exp_ts
        return self.iof.timestamp + int(self.min_exp_time * EXP_TIME_UNIT)

    def get_all_iftokens(self):
        """
        Returns all interface revocation tokens included in the path segment.
        """
        tokens = []
        for asm in self.ases:
            tokens.append(asm.pcbm.ig_rev_token)
            tokens.append(asm.eg_rev_token)
            for pm in asm.pms:
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

    def __len__(self):  # pragma: no cover
        l = self.MIN_LEN
        for asm in self.ases:
            l += len(asm)
        return l

    def short_desc(self):  # pragma: no cover
        """
        Return a short description string of the PathSegment, consisting of a
        truncated hash, the IOF timestamp, and the list of hops.
        """
        desc = []
        desc.append("%s, %s, " % (
            self.get_hops_hash(hex=True)[:12],
            iso_timestamp(self.get_timestamp()),
        ))
        hops = []
        exts = []
        for asm in self.ases:
            hops.append(str(asm.pcbm.isd_as))
            for ext in asm.ext:
                ext_desc = ext.short_desc()
                if not ext_desc:
                    continue
                for line in ext_desc.splitlines():
                    exts.append("  %s" % line)
        desc.append(" > ".join(hops))
        desc.append(", Flags: %s, MTU: %sB" %
                    (PSF.to_str(self.flags), self.mtu))
        if exts:
            return "%s\n%s" % ("".join(desc), "\n".join(exts))
        return "".join(desc)

    def __eq__(self, other):  # pragma: no cover
        if type(other) is not type(self):
            return False
        return (self.iof == other.iof and
                self.trc_ver == other.trc_ver and
                self.ases == other.ases)

    def __str__(self):
        s = []
        s.append("%s(%dB):" % (self.NAME, len(self)))
        s.append("  %s" % self.iof)
        s.append("  trc_ver: %d, if_id: %d, Flags: %s" % (
            self.trc_ver, self.if_id, PSF.to_str(self.flags)))
        for asm in self.ases:
            for line in str(asm).splitlines():
                s.append("  %s" % line)
        return "\n".join(s)

    def __hash__(self):  # pragma: no cover
        return hash(self.get_hops_hash())  # FIMXE(PSz): should add timestamp?

    def flags_(self):
        f = []
        if self.is_sibra():
            f.append(self.FLAG_SIBRA)
        return tuple(f)


def parse_pcb_payload(type_, data):
    type_map = {
        PCBType.SEGMENT: PathSegment,
    }
    if type_ not in type_map:
        raise SCIONParseError("Unsupported pcb type: %s", type_)
    handler = type_map[type_]
    return handler(data.pop())
