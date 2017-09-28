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
from collections import defaultdict
import struct

# External packages
import capnp  # noqa

# SCION
import proto.pcb_capnp as P
from lib.crypto.asymcrypto import sign
from lib.crypto.symcrypto import crypto_hash
from lib.defines import EXP_TIME_UNIT
from lib.errors import SCIONSigVerError
from lib.flagtypes import PathSegFlags as PSF
from lib.packet.asm_exts import RoutingPolicyExt
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.packet.packet_base import Cerealizable
from lib.packet.path import SCIONPath
from lib.packet.scion_addr import ISD_AS
from lib.sibra.pcb_ext import SibraPCBExt
from lib.types import ASMExtType
from lib.util import iso_timestamp

#: Default value for length (in bytes) of a revocation token.
REV_TOKEN_LEN = 32


class PCBMarking(Cerealizable):
    NAME = "PCBMarking"
    P_CLS = P.PCBMarking
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, in_ia, remote_in_ifid, in_mtu, out_ia, remote_out_ifid,
                    hof):  # pragma: no cover
        return cls(cls.P_CLS.new_message(
            inIA=int(in_ia), remoteInIF=remote_in_ifid, inMTU=in_mtu,
            outIA=int(out_ia), remoteOutIF=remote_out_ifid, hof=hof.pack()))

    def inIA(self):  # pragma: no cover
        return ISD_AS(self.p.inIA)

    def outIA(self):  # pragma: no cover
        return ISD_AS(self.p.outIA)

    def hof(self):  # pragma: no cover
        return HopOpaqueField(self.p.hof)

    def sig_pack5(self):
        """
        Pack for signing version 5 (defined by highest field number).
        """
        b = []
        if self.VER != 5:
            raise SCIONSigVerError("PCBMarking.sig_pack5 cannot support version %s", self.VER)
        b.append(self.p.inIA.to_bytes(4, 'big'))
        b.append(self.p.remoteInIF.to_bytes(8, 'big'))
        b.append(self.p.inMTU.to_bytes(2, 'big'))
        b.append(self.p.outIA.to_bytes(4, 'big'))
        b.append(self.p.remoteOutIF.to_bytes(8, 'big'))
        b.append(self.p.hof)
        return b"".join(b)

    def short_desc(self):
        s = []
        s.append("From: %s (IF: %s) To: %s (IF: %s) Ingress MTU:%s" %
                 (self.inIA(), self.p.remoteInIF, self.outIA(),
                  self.p.remoteOutIF, self.p.inMTU))
        s.append("  %s" % self.hof())
        return "\n".join(s)


class ASMarking(Cerealizable):
    NAME = "ASMarking"
    P_CLS = P.ASMarking
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, isd_as, trc_ver, cert_ver, pcbms, hashTreeRoot, mtu, exts=(),
                    ifid_size=12):
        p = cls.P_CLS.new_message(
            isdas=int(isd_as), trcVer=trc_ver, certVer=cert_ver,
            ifIDSize=ifid_size, hashTreeRoot=hashTreeRoot, mtu=mtu)
        p.init("pcbms", len(pcbms))
        for i, pm in enumerate(pcbms):
            p.pcbms[i] = pm.p
        for ext in exts:
            if ext.EXT_TYPE == ASMExtType.ROUTING_POLICY:
                p.exts.routingPolicy = ext.p
        return cls(p)

    def isd_as(self):  # pragma: no cover
        return ISD_AS(self.p.isdas)

    def pcbm(self, idx):  # pragma: no cover
        return PCBMarking(self.p.pcbms[idx])

    def iter_pcbms(self, start=0):  # pragma: no cover
        for i in range(start, len(self.p.pcbms)):
            yield self.pcbm(i)

    def routing_pol_ext(self):
        if self.p.exts.routingPolicy.set:
            return RoutingPolicyExt(self.p.exts.routingPolicy)
        return None

    def add_ext(self, ext):  # pragma: no cover
        """
        Appends a new ASMarking extension.
        """
        d = self.p.to_dict()
        d.setdefault('exts', []).append(ext)
        self.p.from_dict(d)

    def sig_pack8(self):
        """
        Pack for signing version 8 (defined by highest field number).
        """
        b = []
        if self.VER != 8:
            raise SCIONSigVerError("ASMarking.sig_pack8 cannot support version %s", self.VER)
        b.append(self.p.isdas.to_bytes(4, 'big'))
        b.append(self.p.trcVer.to_bytes(4, 'big'))
        b.append(self.p.certVer.to_bytes(4, 'big'))
        b.append(self.p.ifIDSize.to_bytes(1, 'big'))
        for pcbm in self.iter_pcbms():
            b.append(pcbm.sig_pack5())
        b.append(self.p.hashTreeRoot)
        b.append(self.p.mtu.to_bytes(2, 'big'))
        rpe = self.routing_pol_ext()
        if rpe:
            b.append(rpe.sig_pack3())
        # TODO(Sezer): handle other extensions here
        return b"".join(b)

    def short_desc(self):
        desc = []
        desc.append("%s TRC: v%s Cert: v%s AS MTU: %s" %
                    (self.isd_as(), self.p.trcVer, self.p.certVer, self.p.mtu))
        for pcbm in self.iter_pcbms():
            for line in pcbm.short_desc().splitlines():
                desc.append("  %s" % line)
        desc.append("  hashTreeRoot=%s" % self.p.hashTreeRoot)
        desc.append("  sig=%s" % self.p.sig)
        return "\n".join(desc)


class PathSegment(Cerealizable):
    NAME = "PathSegment"
    P_CLS = P.PathSegment
    VER = len(P_CLS.schema.fields) - 1

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
    def from_values(cls, info, sibra_ext=None):  # pragma: no cover
        p = cls.P_CLS.new_message(info=info.pack())
        if sibra_ext:
            p.exts.sibra = sibra_ext.p
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

    def sig_pack3(self):
        """
        Pack for signing version 3 (defined by highest field number).
        """
        if self.VER != 3:
            raise SCIONSigVerError("PathSegment.sig_pack3 cannot support version %s", self.VER)
        b = []
        b.append(self.p.info)
        # ifID field is changed on the fly, and so is ignored.
        for asm in self.iter_asms():
            b.append(asm.sig_pack8())
        if self.is_sibra():
            b.append(self.sibra_ext.sig_pack3())
        return b"".join(b)

    def sign(self, key, set_=True):  # pragma: no cover
        sig = sign(self.sig_pack3(), key)
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
        if self.is_sibra():
            exts.append("  %s" % self.sibra_ext.short_desc())
        desc.append(">".join(hops))
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

    def __eq__(self, other):
        return self.__hash__() == hash(other)

    def __hash__(self):  # pragma: no cover
        return hash(self.get_hops_hash())  # FIMXE(PSz): should add timestamp?


def parse_pcb_payload(p):  # pragma: no cover
    return PathSegment(p)
