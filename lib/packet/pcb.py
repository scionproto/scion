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
import struct

# External packages
from Crypto.Hash import SHA256
import capnp  # noqa

# SCION
import proto.pcb_capnp as P
from lib.crypto.asymcrypto import sign
from lib.crypto.certificate_chain import CertificateChain
from lib.crypto.hash_tree import ConnectedHashTree
from lib.defines import EXP_TIME_UNIT
from lib.flagtypes import PathSegFlags as PSF
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.packet_base import Cerealizable, SCIONPayloadBaseProto
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.packet.path import SCIONPath
from lib.packet.scion_addr import ISD_AS
from lib.sibra.pcb_ext import SibraPCBExt
from lib.types import PayloadClass
from lib.util import iso_timestamp

#: Default value for length (in bytes) of a revocation token.
REV_TOKEN_LEN = 32


class PCBMarking(Cerealizable):
    NAME = "PCBMarking"
    P_CLS = P.PCBMarking

    @classmethod
    def from_values(cls, in_ia, in_ifid, in_mtu, out_ia, out_ifid,
                    hof):  # pragma: no cover
        return cls(cls.P_CLS.new_message(
            inIA=int(in_ia), inIF=in_ifid, inMTU=in_mtu,
            outIA=int(out_ia), outIF=out_ifid, hof=hof.pack()))

    def inIA(self):  # pragma: no cover
        return ISD_AS(self.p.inIA)

    def outIA(self):  # pragma: no cover
        return ISD_AS(self.p.outIA)

    def hof(self):  # pragma: no cover
        return HopOpaqueField(self.p.hof)

    def sig_pack(self, ver):
        """
        Pack for signing up for version 6 (defined by highest field number).
        """
        b = []
        if ver >= 5:
            b.append(self.p.inIA.to_bytes(4, 'big'))
            b.append(self.p.inIF.to_bytes(8, 'big'))
            b.append(self.p.inMTU.to_bytes(2, 'big'))
            b.append(self.p.outIA.to_bytes(4, 'big'))
            b.append(self.p.outIF.to_bytes(8, 'big'))
            b.append(self.p.hof)
        return b"".join(b)

    def short_desc(self):
        s = []
        s.append("From: %s (IF: %s) To: %s (IF: %s) Ingress MTU:%s" %
                 (self.inIA(), self.p.inIF, self.outIA(),
                  self.p.outIF, self.p.inMTU))
        s.append("  %s" % self.hof())
        return "\n".join(s)


class ASMarking(Cerealizable):
    NAME = "ASMarking"
    P_CLS = P.ASMarking

    @classmethod
    def from_values(cls, isd_as, trc_ver, cert_ver, pcbms, hashTreeRoot, mtu,
                    cert_chain, ifid_size=12):
        p = cls.P_CLS.new_message(
            isdas=int(isd_as), trcVer=trc_ver, certVer=cert_ver,
            ifIDSize=ifid_size, hashTreeRoot=hashTreeRoot, mtu=mtu,
            chain=cert_chain.pack(lz4_=True))
        p.init("pcbms", len(pcbms))
        for i, pm in enumerate(pcbms):
            p.pcbms[i] = pm.p
        return cls(p)

    def isd_as(self):  # pragma: no cover
        return ISD_AS(self.p.isdas)

    def pcbm(self, idx):  # pragma: no cover
        return PCBMarking(self.p.pcbms[idx])

    def iter_pcbms(self, start=0):  # pragma: no cover
        for i in range(start, len(self.p.pcbms)):
            yield self.pcbm(i)

    def chain(self):  # pragma: no cover
        return CertificateChain.from_raw(self.p.chain, lz4_=True)

    def add_ext(self, ext):  # pragma: no cover
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
        if ver >= 8:
            b.append(self.p.isdas.to_bytes(4, 'big'))
            b.append(self.p.trcVer.to_bytes(4, 'big'))
            b.append(self.p.certVer.to_bytes(4, 'big'))
            b.append(self.p.ifIDSize.to_bytes(1, 'big'))
            for pcbm in self.iter_pcbms():
                b.append(pcbm.sig_pack(5))
            b.append(self.p.hashTreeRoot)
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

    def short_desc(self):
        desc = []
        desc.append("%s TRC: v%s Cert: v%s AS MTU: %s" %
                    (self.isd_as(), self.p.trcVer, self.p.certVer, self.p.mtu))
        for pcbm in self.iter_pcbms():
            for line in pcbm.short_desc().splitlines():
                desc.append("  %s" % line)
        desc.append("  hashTreeRoot=%s" % self.p.hashTreeRoot)
        desc.append("  sig=%s" % self.p.sig)
        desc.append("  chain=%s" % self.p.chain)
        return "\n".join(desc)


class PathSegment(SCIONPayloadBaseProto):
    NAME = "PathSegment"
    PAYLOAD_CLASS = PayloadClass.PCB
    P_CLS = P.PathSegment

    def __init__(self, p):  # pragma: no cover
        super().__init__(p)
        self._min_exp = float("inf")
        self._setup()

    def _setup(self):
        self.info = InfoOpaqueField(self.p.info)
        self._calc_min_exp()
        self.sibra_ext = None
        if self.is_sibra():
            self.sibra_ext = SibraPCBExt(self.p.exts.sibra)

    @classmethod
    def from_values(cls, info, rev_infos=None,
                    sibra_ext=None):  # pragma: no cover
        p = cls.P_CLS.new_message(info=info.pack())
        if sibra_ext:
            p.exts.sibra = sibra_ext.p
        if rev_infos:
            p.exts.init("revInfos", len(rev_infos))
            for i, info in enumerate(rev_infos):
                p.exts.revInfos[i] = info.copy()
        return cls(p)

    def _calc_min_exp(self):
        # NB: only the expiration time of the first pcbm is considered.
        for asm in self.iter_asms():
            self._min_exp = min(self._min_exp, asm.pcbm(0).hof().exp_time)

    def asm(self, idx):  # pragma: no cover
        return ASMarking(self.p.asms[idx])

    def iter_asms(self, start=0):  # pragma: no cover
        for i in range(start, len(self.p.asms)):
            yield self.asm(i)

    def is_sibra(self):  # pragma: no cover
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

    def sign(self, key, set_=True):  # pragma: no cover
        assert not self.p.asms[-1].sig
        sig = sign(self.sig_pack(3), key)
        if set_:
            self.p.asms[-1].sig = sig
        return sig

    def add_asm(self, asm):  # pragma: no cover
        """
        Appends a new ASMarking block.
        """
        d = self.p.to_dict()
        d.setdefault('asms', []).append(asm.p)
        self.p.from_dict(d)
        self._update_info()
        self._min_exp = min(self._min_exp, asm.pcbm(0).hof().exp_time)

    def _update_info(self):  # pragma: no cover
        self.info.hops = len(self.p.asms)
        self.p.info = self.info.pack()

    def add_sibra_ext(self, ext_p):  # pragma: no cover
        self.p.exts.sibra = ext_p.copy()
        self.sibra_ext = SibraPCBExt(self.p.exts.sibra)

    def add_rev_infos(self, rev_infos):  # pragma: no cover
        """
        Appends a list of revocations to the PCB. Replaces existing
        revocations with newer ones.
        """
        if not rev_infos:
            return
        existing = {}
        current_epoch = ConnectedHashTree.get_current_epoch()
        for i in range(len(self.p.exts.revInfos)):
            orphan = self.p.exts.revInfos.disown(i)
            info_p = orphan.get()
            if info_p.epoch >= current_epoch:
                existing[(info_p.isdas, info_p.ifID)] = orphan
        # Remove revocations for which we already have a newer one.
        filtered = []
        for info in rev_infos:
            if (info.p.epoch >= current_epoch and
                    (info.p.isdas, info.p.ifID) not in existing):
                filtered.append(info)
        self.p.exts.init("revInfos", len(existing) + len(filtered))
        for i, orphan in enumerate(existing.values()):
            self.p.exts.revInfos.adopt(i, orphan)
        n_existing = len(existing)
        for i, info in enumerate(filtered):
            self.p.exts.revInfos[n_existing + i] = info.p

    def remove_crypto(self):  # pragma: no cover
        """
        Removes the signatures and certificates from each AS block.
        """
        for asm in self.iter_asms():
            asm.remove_sig()
            asm.remove_chain()

    def get_path(self, reverse_direction=False):
        """
        Returns the list of HopOpaqueFields in the path.
        """
        hofs = []
        info = InfoOpaqueField(self.p.info)
        asms = list(self.iter_asms())
        if reverse_direction:
            asms = reversed(asms)
            info.up_flag ^= True
        for asm in asms:
            hofs.append(asm.pcbm(0).hof())
        return SCIONPath.from_values(info, hofs)

    def first_ia(self):  # pragma: no cover
        return self.asm(0).isd_as()

    def last_ia(self):  # pragma: no cover
        return self.asm(-1).isd_as()

    def last_hof(self):  # pragma: no cover
        if self.p.asms:
            return self.asm(-1).pcbm(0).hof()
        return None

    def get_hops_hash(self, hex=False):  # pragma: no cover
        """
        Returns the hash over all triples (ISD_AS, IG_IF, EG_IF) included in
        the path segment.
        """
        h = SHA256.new()
        for asm in self.iter_asms():
            pcbm = asm.pcbm(0)
            h.update(asm.isd_as().pack() +
                     struct.pack("!QQ", pcbm.p.inIF, pcbm.p.outIF))
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

    def get_expiration_time(self):  # pragma: no cover
        """
        Returns the expiration time of the path segment in real time. If a PCB
        extension in the last ASMarking supplies an expiration time, use that.
        Otherwise fall-back to the standard expiration time calculation.
        """
        if self.is_sibra():
            return self.sibra_ext.exp_ts()
        return self.info.timestamp + int(self._min_exp * EXP_TIME_UNIT)

    def flags(self):  # pragma: no cover
        f = 0
        if self.is_sibra():
            f |= PSF.SIBRA
        return f

    def rev_info(self, idx):
        return RevocationInfo(self.p.exts.revInfos[idx])

    def iter_rev_infos(self, start=0):
        for i in range(start, len(self.p.exts.revInfos)):
            yield self.rev_info(i)

    def get_rev_map(self):
        """
        Returns a dict (ISD_AS, IF) -> RevocationInfo, if there are any
        revocations in the PCB extensions, otherwise an empty dict.
        """
        result = {}
        for rev_info in self.iter_rev_infos():
            key = (rev_info.isd_as(), rev_info.p.ifID)
            result[key] = rev_info

        return result

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
        for rev_info in self.iter_rev_infos():
            exts.append("  %s" % rev_info.short_desc())
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
        for rev_info in self.iter_rev_infos():
            for line in rev_info.short_desc().splitlines():
                s.append("  %s" % line)
        return "\n".join(s)

    def __hash__(self):  # pragma: no cover
        return hash(self.get_hops_hash())  # FIMXE(PSz): should add timestamp?


def parse_pcb_payload(p):  # pragma: no cover
    return PathSegment(p)
