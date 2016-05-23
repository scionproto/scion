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
:mod:`seg_recs` --- Path Segment records
============================================
"""
# Stdlib
from collections import defaultdict

# External
import capnp  # noqa

# SCION
import proto.path_mgmt_capnp as P
from lib.packet.path_mgmt.base import PathMgmtPayloadBase
from lib.packet.pcb import PathSegment
from lib.types import PathMgmtType as PMT, PathSegmentType as PST


class PathSegmentRecords(PathMgmtPayloadBase):
    """
    Path Record class used for sending list of down/up-paths. Paths are
    represented as objects of the PathSegment class.
    """
    P_CLS = P.SegRecs

    def __init__(self, p):  # pragma: no cover
        super().__init__(p)
        self.pcbs = defaultdict(list)
        for entry in self.p.pcbs:
            self.pcbs[entry.type].append(PathSegment(entry.raw))

    @classmethod
    def from_values(cls, pcb_dict):
        """
        :param pcb_dict: dict of {seg_type: [pcbs]}
        """
        unrolled = []
        for type_, pcbs in pcb_dict.items():
            for pcb in pcbs:
                unrolled.append((type_, pcb))
        p = cls.P_CLS.new_message()
        p.init("pcbs", len(unrolled))
        for i, (type_, pcb) in enumerate(unrolled):
            p.pcbs[i].type = type_
            p.pcbs[i].raw = pcb.pack()
        return cls(p)

    def __str__(self):
        s = []
        s.append("%s:" % self.NAME)
        for type_ in [PST.UP, PST.DOWN, PST.CORE]:
            if self.pcbs[type_]:
                s.append("  %s:" % PST.to_str(type_))
                for pcb in self.pcbs[type_]:
                    s.append("    %s" % pcb.short_desc())
        return "\n".join(s)


class PathRecordsReply(PathSegmentRecords):
    NAME = "PathRecordsReply"
    PAYLOAD_TYPE = PMT.REPLY


class PathRecordsReg(PathSegmentRecords):
    NAME = "PathRecordsReg"
    PAYLOAD_TYPE = PMT.REG


class PathRecordsSync(PathSegmentRecords):
    NAME = "PathRecordsSync"
    PAYLOAD_TYPE = PMT.SYNC
