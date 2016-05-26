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

# External packages
from Crypto.Hash import SHA256
import capnp  # noqa

# SCION
import proto.pcb_capnp as P
from lib.crypto.asymcrypto import sign
from lib.crypto.certificate import CertificateChain
from lib.defines import EXP_TIME_UNIT
from lib.errors import SCIONParseError
from lib.flagtypes import PathSegFlags as PSF
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.packet_base import Cerealizable, SCIONPayloadBaseProto
from lib.packet.path import SCIONPath  # , min_mtu
from lib.packet.scion_addr import ISD_AS
from lib.sibra.pcb_ext import SibraPCBExt
from lib.types import PCBType, PayloadClass
from lib.util import hex_str, iso_timestamp

#: Default value for length (in bytes) of a revocation token.
REV_TOKEN_LEN = 32


class PCBMarking(Cerealizable):
    """
    Pack all fields for a specific PCB marking, which include: ISD and AS
    numbers, the HopOpaqueField, and the revocation token for the ingress
    interfaces included in the HOF. (Revocation token for egress interface is
    included within ASMarking.)
    """
    NAME = "PCBMarking"
    P_CLS = P.PCBMarking

    @classmethod
    def from_values(cls, in_ia, in_ifid, in_mtu, out_ia, out_ifid, hof,
                    ig_rev_token):  # pragma: no cover
        """
        Returns PCBMarking with fields populated from values.

        :param isd_as: ISD_AS object.
        :param hof: HopOpaqueField object.
        :param ig_rev_token: Revocation token for the ingress if
                             in the HopOpaqueField.
        """
        return cls(cls.P_CLS.new_message(
            inIA=str(in_ia), inIF=in_ifid, inMTU=in_mtu,
            outIA=str(out_ia), outIF=out_ifid, hof=hof.pack(),
            igRevToken=ig_rev_token))

    def inIA(self):
        return ISD_AS(self.p.inIA)

    def outIA(self):
        return ISD_AS(self.p.outIA)

    def hof(self):
        return HopOpaqueField(self.p.hof)

    def sig_pack(self, ver):
        """
        Pack for signing up for version 6 (defined by highest field number).
        """
        b = []
        if ver >= 6:
            b.append(self.p.inIA.encode("utf8"))
            b.append(self.p.inIF.to_bytes(8, 'big'))
            b.append(self.p.inMTU.to_bytes(2, 'big'))
            b.append(self.p.outIA.encode("utf8"))
            b.append(self.p.outIF.to_bytes(8, 'big'))
            b.append(self.p.hof)
            b.append(self.p.igRevToken)
        return b"".join(b)

    def __eq__(self, other):  # pragma: no cover
        return self.p == other.p

    def __str__(self):
        s = []
        s.append("%s: From: %s (IF: %s) To: %s (IF: %s) Ingress MTU:%s" %
                 (self.NAME, self.isd_as(), self.p.ifID, self.p.mtu))
        s.append("  %s" % self.hof())
        s.append("  ig_rev_token: %s" % hex_str(self.p.igRevToken))
        return "\n".join(s)


class ASMarking(Cerealizable):
    NAME = "ASMarking"
    P_CLS = P.ASMarking

    @classmethod
    def from_values(cls, isd_as, trc_ver, cert_ver, pcbms, eg_rev_token, mtu,
                    cert_chain, ifid_size=12, rev_infos=()):
        p = cls.P_CLS.new_message(
            isdas=str(isd_as), trcVer=trc_ver, certVer=cert_ver,
            ifIDSize=ifid_size, egRevToken=eg_rev_token, mtu=mtu,
            chain=cert_chain.pack(lz4_=True))
        p.init("pcbms", len(pcbms))
        for i, pm in enumerate(pcbms):
            p.pcbms[i] = pm.p
        p.exts.init("revInfos", len(rev_infos))
        for i, rev_info in enumerate(rev_infos):
            p.exts.revInfos[i] = rev_info.pack()
        return cls(p)

    def isd_as(self):
        return ISD_AS(self.p.isdas)

    def pcbm(self, idx):
        return PCBMarking(self.p.pcbms[idx])

    def iter_pcbms(self, start=0):
        for i in range(start, len(self.p.pcbms)):
            yield self.pcbm(i)

    def chain(self):
        return CertificateChain(self.p.chain, lz4_=True)

    def add_ext(self, ext):
        """
        Appends a new ASMarking extension.
        """
        d = self.p.to_dict()
        d.setdefault('exts', []).append(ext)
        self.p.from_dict(d)

    def sig_pack(self, ver):
        """
        Pack for signing up for given version (defined by highest field number).
        """
        b = []
        if ver >= 9:
            b.append(self.p.isdas.encode("utf8"))
            b.append(self.p.trcVer.to_bytes(4, 'big'))
            b.append(self.p.certVer.to_bytes(4, 'big'))
            b.append(self.p.ifIDSize.to_bytes(1, 'big'))
            for pcbm in self.iter_pcbms():
                b.append(pcbm.sig_pack(6))
            b.append(self.p.egRevToken)
            b.extend(self.p.exts.revInfos)
            b.append(self.p.mtu.to_bytes(2, 'big'))
            b.append(self.p.chain)
        return b"".join(b)

    def remove_sig(self):  # pragma: no cover
        """
        Removes the signature from the AS block.
        """
        self.p.sig = b''

    def remove_chain(self):  # pragma: no cover
        """
        Removes the certificate chain from the AS block.
        """
        self.p.chain = b''


class PathSegment(SCIONPayloadBaseProto):
    NAME = "PathSegment"
    PAYLOAD_CLASS = PayloadClass.PCB
    PAYLOAD_TYPE = PCBType.SEGMENT
    P_CLS = P.PathSegment

    def __init__(self, p):
        super().__init__(p)
        self.info = InfoOpaqueField(p.info)
        self.sibra_ext = None
        if p.exts.sibra.info:
            self.sibra_ext = SibraPCBExt(self.p.exts.sibra)

    @classmethod
    def from_values(cls, info, sibra_ext=None):  # pragma: no cover
        p = cls.P_CLS.new_message(info=info.pack())
        if sibra_ext:
            p.exts.sibra = sibra_ext.p
        return cls(p)

    def asm(self, idx):
        return ASMarking(self.p.asms[idx])

    def iter_asms(self, start=0):
        for i in range(start, len(self.p.asms)):
            yield self.asm(i)

    def is_sibra(self):
        return bool(self.p.exts.sibra.id)

    def sig_pack(self, ver=3):
        b = []
        if ver >= 3:
            b.append(self.p.info)
            # ifID field is changed on the fly, and so is ignored.
            for asm in self.iter_asms():
                b.append(asm.sig_pack(9))
            if self.is_sibra():
                b.append(self.sibra_ext.sig_pack(2))
        return b"".join(b)

    def sign(self, key, set_=True):
        assert not self.p.asms[-1].sig
        sig = sign(self.sig_pack(3), key)
        if set_:
            self.p.asms[-1].sig = sig
        return sig

    def add_asm(self, asm):
        """
        Appends a new ASMarking block.
        """
        d = self.p.to_dict()
        d.setdefault('asms', []).append(asm.p)
        self.p.from_dict(d)
        self._update_info()

    def _update_info(self):
        self.info.hops = len(self.p.asms)
        self.p.info = self.info.pack()

    def add_sibra_ext(self, ext_p):
        self.p.exts.sibra = ext_p.copy()
        self.sibra_ext = SibraPCBExt(self.p.exts.sibra)

    def remove_crypto(self):  # pragma: no cover
        """
        Remover the signatures and certificates from each AS block.
        """
        for asm in self.iter_asms():
            asm.remove_sig()
            asm.remove_chain()

    def get_path(self, reverse_direction=False):
        """
        Returns the list of HopOpaqueFields in the path.
        """
        hofs = []
        info = copy.deepcopy(self.info)
        asms = list(self.iter_asms())
        if reverse_direction:
            asms = reversed(asms)
            info.up_flag ^= True
        for asm in asms:
            hofs.append(asm.pcbm(0).hof())
        return SCIONPath.from_values(info, hofs)

    def first_ia(self):
        return self.asm(0).isd_as()

    def last_ia(self):
        return self.asm(-1).isd_as()

    def last_hof(self):
        if self.p.asms:
            return self.asm(-1).pcbm(0).hof()
        return None

    def get_hops_hash(self, hex=False):
        """
        Returns the hash over all the interface revocation tokens included in
        the path segment.
        """
        h = SHA256.new()
        for token in self.get_all_iftokens():
            h.update(token)
        if hex:
            return h.hexdigest()
        return h.digest()

    def get_n_peer_links(self):  # pragma: no cover
        """Return the total number of peer links in the PathSegment."""
        n = 0
        for asm in self.p.asms:
            n += len(asm.pcbms) - 1
        return n

    def get_n_hops(self):  # pragma: no cover
        """Return the number of hops in the PathSegment."""
        return len(self.p.asms)

    def get_timestamp(self):  # pragma: no cover
        """Returns the creation timestamp of this PathSegment."""
        return self.info.timestamp

    def set_timestamp(self, timestamp):  # pragma: no cover
        """Updates the timestamp in the IOF."""
        assert timestamp < 2 ** 32 - 1
        self.info.timestamp = timestamp
        self._update_info()

    def get_expiration_time(self):
        """
        Returns the expiration time of the path segment in real time. If a PCB
        extension in the last ASMarking supplies an expiration time, use that.
        Otherwise fall-back to the standard expiration time calculation.
        """
        if self.is_sibra():
            return self.sibra_ext.exp_ts()
        # FIXME(kormat): need to get min.
        return self.info.timestamp + int((2 ** 8 - 1) * EXP_TIME_UNIT)

    def get_all_iftokens(self):
        """
        Returns all interface revocation tokens included in the path segment.
        """
        tokens = []
        for asm in self.p.asms:
            for pcbm in asm.pcbms:
                tokens.append(pcbm.igRevToken)
            tokens.append(asm.egRevToken)
        return tokens

    def flags(self):
        f = 0
        if self.is_sibra():
            f |= PSF.SIBRA
        return f

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
        for asm in self.iter_asms():
            hops.append(str(asm.isd_as()))
        exts = []
        if self.is_sibra():
            exts.append("  %s" % self.sibra_ext.short_desc())
        desc.append(" > ".join(hops))
        if exts:
            return "%s\n%s" % ("".join(desc), "\n".join(exts))
        return "".join(desc)

    def __str__(self):
        s = []
        s.append("%s:" % self.NAME)
        s.append("  %s" % self.info)
        for asm in self.iter_asms():
            for line in asm.short_desc().splitlines():
                s.append("  %s" % line)
        if self.sibra_ext:
            for line in str(self.sibra_ext).splitlines():
                s.append("  %s" % line)
        return "\n".join(s)

    def __hash__(self):  # pragma: no cover
        return hash(self.get_hops_hash())  # FIMXE(PSz): should add timestamp?


def parse_pcb_payload(type_, data):
    type_map = {
        PCBType.SEGMENT: PathSegment.from_raw,
    }
    if type_ not in type_map:
        raise SCIONParseError("Unsupported pcb type: %s", type_)
    handler = type_map[type_]
    return handler(data.pop())
