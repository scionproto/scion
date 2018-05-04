# Copyright 2015 ETH Zurich
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
:mod:`info` --- SIBRA Segment Info PCB extension
================================================
"""
# External
import capnp  # noqa

# SCION
import proto.sibra_capnp as P
from lib.errors import SCIONSigVerError
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS
from lib.sibra.ext.info import ResvInfoSteady
from lib.sibra.ext.sof import SibraOpaqueField
from lib.util import hex_str


class SibraPCBExt(Cerealizable):  # pragma: no cover
    """
    SIBRA PCB extension. Used to attach reservation info to a PathSegment when
    registering a SIBRA steady path.
    """
    NAME = "SibraPCBExt"
    P_CLS = P.SibraPCBExt
    VER = len(P_CLS.schema.fields) - 1

    def __init__(self, p):
        super().__init__(p)
        self.info = ResvInfoSteady(p.info)

    @classmethod
    def from_values(cls, id_, info, sofs, cons_dir=False):
        p = cls.P_CLS.new_message(id=id_, info=info.pack(), cons_dir=cons_dir)
        p.init("sofs", len(sofs))
        for i, sof in enumerate(sofs):
            p.sofs[i] = sof.pack()
        return cls(p)

    def isd_as(self):
        return ISD_AS(self.p.id[:ISD_AS.LEN])

    def sof(self, idx):
        return SibraOpaqueField(self.p.sofs[idx])

    def iter_sofs(self, start=0):
        for i in range(start, len(self.p.sofs)):
            yield self.sof(i)

    def exp_ts(self):
        return self.info.exp_ts()

    def sig_pack3(self):
        """
        Pack for signing version 3 (defined by highest field number).
        """
        if self.VER != 3:
            raise SCIONSigVerError(
                "SibraPCBExt.sig_pack3 cannot support version %s", self.VER)
        b = []
        b.append(self.p.id)
        b.append(self.p.info)
        b.append(self.p.cons_dir.to_bytes(1, 'big'))
        for sof in self.p.sofs:
            b.append(sof)
        return b"".join(b)

    def __str__(self):
        a = []
        a.append(self.short_desc())
        for sof in self.iter_sofs():
            a.append("  %s" % sof)
        return "\n".join(a)

    def short_desc(self):
        a = []
        a.append("%s: id: %s (owner: %s) ConsDir? %s" %
                 (self.NAME, hex_str(self.p.id), self.isd_as(), self.p.cons_dir))
        for line in str(self.info).splitlines():
            a.append("  %s" % line)
        return "\n".join(a)
