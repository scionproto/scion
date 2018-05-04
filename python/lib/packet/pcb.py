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
from collections import defaultdict

# External packages
import capnp  # noqa

# SCION
import proto.path_seg_capnp as P
from lib.crypto.symcrypto import crypto_hash
from lib.defines import EXP_TIME_UNIT
from lib.packet.asm_exts import RoutingPolicyExt
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.packet_base import Cerealizable
from lib.packet.path import SCIONPath
from lib.packet.proto_sign import ProtoSign, ProtoSignedBlob, ProtoSignType
from lib.packet.scion_addr import ISD_AS
from lib.types import ASMExtType, LinkType
from lib.util import iso_timestamp

#: Default value for length (in bytes) of a revocation token.
REV_TOKEN_LEN = 32


class PCBMarking(Cerealizable):
    NAME = "PCBMarking"
    P_CLS = P.HopEntry

    @classmethod
    def from_values(cls, in_ia, remote_in_ifid, in_mtu, out_ia,
                    remote_out_ifid, hof):  # pragma: no cover
        return cls(cls.P_CLS.new_message(
            inIA=int(in_ia), remoteInIF=remote_in_ifid, inMTU=in_mtu,
            outIA=int(out_ia), remoteOutIF=remote_out_ifid, hopF=hof.pack()))

    def inIA(self):  # pragma: no cover
        return ISD_AS(self.p.inIA)

    def outIA(self):  # pragma: no cover
        return ISD_AS(self.p.outIA)

    def hof(self):  # pragma: no cover
        return HopOpaqueField(self.p.hopF)

    def short_desc(self):
        s = []
        s.append("From: %s (IF: %s) To: %s (IF: %s) Ingress MTU:%s" %
                 (self.inIA(), self.p.remoteInIF, self.outIA(),
                  self.p.remoteOutIF, self.p.inMTU))
        s.append("  %s" % self.hof())
        return "\n".join(s)


class ASMarking(Cerealizable):
    NAME = "ASMarking"
    P_CLS = P.ASEntry

    @classmethod
    def from_values(cls, isd_as, trc_ver, cert_ver, pcbms, mtu, exts=(), ifid_size=12):
        p = cls.P_CLS.new_message(
            isdas=int(isd_as), trcVer=trc_ver, certVer=cert_ver,
            ifIDSize=ifid_size, mtu=mtu)
        p.init("hops", len(pcbms))
        for i, pm in enumerate(pcbms):
            p.hops[i] = pm.p
        for ext in exts:
            if ext.EXT_TYPE == ASMExtType.ROUTING_POLICY:
                p.exts.routingPolicy = ext.p
        return cls(p)

    def isd_as(self):  # pragma: no cover
        return ISD_AS(self.p.isdas)

    def pcbm(self, idx):  # pragma: no cover
        return PCBMarking(self.p.hops[idx])

    def iter_pcbms(self, start=0):  # pragma: no cover
        for i in range(start, len(self.p.hops)):
            yield self.pcbm(i)

    def routing_pol_ext(self):
        if self.p.exts.routingPolicy.set:
            return RoutingPolicyExt(self.p.exts.routingPolicy)
        return None

    def short_desc(self):
        desc = []
        desc.append("%s TRC: v%s Cert: v%s AS MTU: %s" %
                    (self.isd_as(), self.p.trcVer, self.p.certVer, self.p.mtu))
        for pcbm in self.iter_pcbms():
            for line in pcbm.short_desc().splitlines():
                desc.append("  %s" % line)
        return "\n".join(desc)


class PathSegment(Cerealizable):
    NAME = "PathSegment"
    P_CLS = P.PathSegment

    def __init__(self, p):  # pragma: no cover
        super().__init__(p)
        self._min_exp = float("inf")
        self._setup()
        self.ifID = 0

    def _setup(self):
        self.sdata = PathSegmentSignedData.from_raw(self.p.sdata)
        self._asms = []
        for sblob in self.p.asEntries:
            self._asms.append(ASMarking.from_raw(sblob.blob))
        self._calc_min_exp()

    @classmethod
    def from_values(cls, info):  # pragma: no cover
        return cls(cls.P_CLS.new_message(sdata=PathSegmentSignedData.from_values(info).pack()))

    def pcb(self):
        return PCB.from_values(self, self.ifID)

    def infoF(self):
        info = InfoOpaqueField(self.sdata.p.infoF)
        info.hops = len(self.p.asEntries)
        return info

    def copy(self):
        new = super().copy()
        new.ifID = self.ifID
        return new

    def _calc_min_exp(self):
        # NB: only the expiration time of the first pcbm is considered.
        for asm in self.iter_asms():
            self._min_exp = min(self._min_exp, asm.pcbm(0).hof().exp_time)

    def asm(self, idx):  # pragma: no cover
        return self._asms[idx]

    def iter_asms(self, start=0):  # pragma: no cover
        for asm in self._asms[start:]:
            yield asm

    def sign(self, key):  # pragma: no cover
        assert len(self.p.asEntries) > 0, "No ASMarkings to sign"
        s = ProtoSign(self.p.asEntries[-1].sign)
        s.sign(key, self._sig_input())

    def verify(self, key, idx=None):
        if idx is None:
            idx = len(self.p.asEntries) - 1
        s = ProtoSign(self.p.asEntries[idx].sign)
        return s.verify(key, self._sig_input(idx))

    def _sig_input(self, idx=None):
        if idx is None:
            idx = len(self.p.asEntries) - 1
        b = [self.p.sdata]
        for i in range(idx+1):
            sblob = self.p.asEntries[i]
            b.append(sblob.blob)
            ssign = ProtoSign(sblob.sign)
            b.append(ssign.sig_pack(i != idx))
        return b"".join(b)

    def add_asm(self, asm, sig_type=ProtoSignType.NONE, sig_src=b""):  # pragma: no cover
        """
        Appends a new ASMarking block.
        """
        d = self.p.to_dict()
        sblob = ProtoSignedBlob.from_values(asm.pack(), sig_type, sig_src)
        d.setdefault('asEntries', []).append(sblob.p)
        self.p.from_dict(d)
        self._asms.append(asm)
        self._min_exp = min(self._min_exp, asm.pcbm(0).hof().exp_time)

    def get_trcs_certs(self):
        """
        Returns a dict of all trcs' versions and a dict of all certificates'
        versions used in this PCB.
        """
        trcs = defaultdict(set)
        certs = defaultdict(set)
        for asm in self.iter_asms():
            isd_as = asm.isd_as()
            isd = isd_as[0]
            trcs[isd].add(asm.p.trcVer)
            certs[isd_as].add(asm.p.certVer)
        return trcs, certs

    def get_path(self, reverse_direction=False):
        """
        Returns the list of HopOpaqueFields in the path.
        """
        hofs = []
        info = self.infoF()
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
        if self.p.asEntries:
            return self.asm(-1).pcbm(0).hof()
        return None

    def get_hops_hash(self, hex=False):  # pragma: no cover
        """
        Returns the hash over all triples (ISD_AS, IG_IF, EG_IF) included in
        the path segment.
        """
        data = []
        for asm in self.iter_asms():
            pcbm = asm.pcbm(0)
            data.append(asm.isd_as().pack())
            hof = pcbm.hof()
            data.append(struct.pack("!QQ", hof.ingress_if, hof.egress_if))
        data = b"".join(data)
        if hex:
            return crypto_hash(data).hex()
        return crypto_hash(data)

    def get_n_peer_links(self):  # pragma: no cover
        """Return the total number of peer links in the PathSegment."""
        n = 0
        for asm in self._asms:
            n += len(asm.p.hops) - 1
        return n

    def get_n_hops(self):  # pragma: no cover
        """Return the number of hops in the PathSegment."""
        return len(self.p.asEntries)

    def get_timestamp(self):  # pragma: no cover
        """Returns the creation timestamp of this PathSegment."""
        return self.infoF().timestamp

    def get_expiration_time(self):  # pragma: no cover
        """
        Returns the expiration time of the path segment in real time. If a PCB
        extension in the last ASMarking supplies an expiration time, use that
        (XXX(kormat): not currently implemented).
        Otherwise fall-back to the standard expiration time calculation.
        """
        return self.infoF().timestamp + int(self._min_exp * EXP_TIME_UNIT)

    def short_id(self):  # pragma: no cover
        """
        Return a 12-byte hex ID identifying the PCB (mostly for logging purposes).
        """
        return self.get_hops_hash(hex=True)[:12]

    def short_desc(self):  # pragma: no cover
        """
        Return a short description string of the PathSegment, consisting of a
        truncated hash, the IOF timestamp, and the list of hops.
        """
        desc = []
        desc.append("%s, %s, " % (self.short_id(), iso_timestamp(self.get_timestamp())))
        hops = []
        for asm in self.iter_asms():
            hop = []
            hof = asm.pcbm(0).hof()
            if hof.ingress_if:
                hop.append("%d " % hof.ingress_if)
            hop.append("%s" % asm.isd_as())
            if hof.egress_if:
                hop.append(" %d" % hof.egress_if)
            hops.append("".join(hop))
        exts = []
        desc.append(">".join(hops))
        if exts:
            return "%s\n%s" % ("".join(desc), "\n".join(exts))
        return "".join(desc)

    def rev_match(self, rev_info, core):
        """
        Check if a revocation matches the current PCB
        :param rev_info: Revocation Info to check
        :type rev_info: RevocationInfo
        :return: Tuple(boolean, LinkType)
        """
        for asm in self.iter_asms():
            if rev_info.isd_as() != asm.isd_as():
                continue
            for i, pcbm in enumerate(asm.iter_pcbms()):
                hof = pcbm.hof()
                if rev_info.p.ifID == hof.ingress_if:
                    if core:
                        return True, LinkType.CORE
                    return True, LinkType.PARENT if i == 0 else LinkType.PEER
                if rev_info.p.ifID == hof.egress_if:
                    return True, LinkType.CORE if core else LinkType.CHILD
        return False, None

    def is_sibra(self):
        return False  # Nope! Kept for compatibility with path server.

    def __str__(self):
        s = []
        s.append("%s:" % self.NAME)
        s.append("  %s" % self.infoF())
        for asm in self.iter_asms():
            for line in asm.short_desc().splitlines():
                s.append("  %s" % line)
        return "\n".join(s)

    def __eq__(self, other):
        return self.__hash__() == hash(other)

    def __hash__(self):  # pragma: no cover
        return hash(self.get_hops_hash())  # FIMXE(PSz): should add timestamp?


class PathSegmentSignedData(Cerealizable):
    NAME = "PathSegmentSignedData"
    P_CLS = P.PathSegmentSignedData

    @classmethod
    def from_values(cls, info):  # pragma: no cover
        return cls(cls.P_CLS.new_message(infoF=info.pack()))

    def sig_pack(self):
        return self.p.infoF


class PCB(Cerealizable):
    NAME = "PCB"
    P_CLS = P.PCB

    @classmethod
    def from_values(cls, pseg, ifid=0):  # pragma: no cover
        return cls(cls.P_CLS.new_message(pathSeg=pseg.p, ifID=ifid))

    def pseg(self):
        p = PathSegment(self.p.pathSeg)
        p.ifID = self.p.ifID
        return p
