# Copyright 2016 ETH Zurich
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
:mod:`resv` --- Reservation block
=================================
"""
# SCION
from lib.sibra.ext.info import (
    ResvInfoBase,
    ResvInfoEphemeral,
    ResvInfoSteady,
)
from lib.sibra.ext.sof import SibraOpaqueField
from lib.packet.ext_hdr import HopByHopExtension
from lib.packet.packet_base import Serializable
from lib.util import Raw


class ResvBlockBase(Serializable):
    """
    Base class for a SIBRA reservation block. This can either be an active
    block, in which case it's used for routing the packet; or a request block,
    in which case it's evaluated and filled in by each hop on the path. If any
    hop rejects the request, then this block will be replaced by an offers
    block.

    A reservation block is made up of a reservation info field, and a list of
    SIBRA opaque fields.

     0B       1        2        3        4        5        6        7
     +--------+--------+--------+--------+--------+--------+--------+--------+
     | Reservation Info                                                      |
     +--------+--------+--------+--------+--------+--------+--------+--------+
     | SIBRA Opaque Field (8B)                                               |
     +--------+--------+--------+--------+--------+--------+--------+--------+
     |...                                                                    |
     +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    LINE_LEN = HopByHopExtension.LINE_LEN
    MIN_LEN = ResvInfoBase.LEN

    def __init__(self, raw=None):  # pragma: no cover
        self.info = None
        self.sofs = []
        self.num_hops = 0
        super().__init__(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self.info = self.RESVINFO(data.pop(self.RESVINFO.LEN))
        self.num_hops = len(data) // SibraOpaqueField.LEN
        while data:
            raw_sof = data.pop(SibraOpaqueField.LEN)
            if raw_sof == bytes(SibraOpaqueField.LEN):
                break
            self.sofs.append(SibraOpaqueField(raw_sof))

    @classmethod
    def from_values(cls, info, num_hops):  # pragma: no cover
        inst = cls()
        inst.info = info
        inst.num_hops = num_hops
        return inst

    def pack(self):
        assert self.num_hops >= len(self.sofs)
        raw = []
        raw.append(self.info.pack())
        for sof in self.sofs:
            raw.append(sof.pack())
        for i in range(len(self.sofs), self.num_hops):
            raw.append(bytes(SibraOpaqueField.LEN))
        return b"".join(raw)

    def add_hop(self, ingress, egress, prev_raw, key, path_ids):
        """
        Add a SIBRA Opaque Field to the reservation block. This happens when a
        request has been accepted by a hop on the path.
        """
        assert len(self.sofs) + 1 <= self.num_hops
        sof = SibraOpaqueField.from_values(ingress, egress)
        sof.mac = sof.calc_mac(self.info, key, path_ids, prev_raw)
        self.sofs.append(sof)

    def __len__(self):  # pragma: no cover
        return (1 + self.num_hops) * self.LINE_LEN

    def __str__(self):
        tmp = ["%s(%dB): Num hops: %s" % (self.NAME, len(self), self.num_hops)]
        for line in str(self.info).splitlines():
            tmp.append("  %s" % line)
        for sof in self.sofs:
            tmp.append("  %s" % sof)
        return "\n".join(tmp)


class ResvBlockSteady(ResvBlockBase):
    NAME = "ResvBlockSteady"
    RESVINFO = ResvInfoSteady


class ResvBlockEphemeral(ResvBlockBase):
    NAME = "ResvBlockEphemeral"
    RESVINFO = ResvInfoEphemeral
