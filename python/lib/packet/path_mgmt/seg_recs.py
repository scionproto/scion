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
# External
import capnp  # noqa

# SCION
import proto.path_mgmt_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.packet.pcb import PathSegment
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.types import PathSegmentType as PST


class PathSegmentRecords(Cerealizable):  # pragma: no cover
    """
    Path Record class used for sending list of down/up-paths. Paths are
    represented as objects of the PathSegment class.
    """
    NAME = "PathSegmentRecords"
    P_CLS = P.SegRecs

    @classmethod
    def from_values(cls, pcb_dict, rev_infos=None):
        """
        :param pcb_dict: dict of {seg_type: [pcbs]}
        :param rev_infos: list of RevocationInfo objects
        """
        if not rev_infos:
            rev_infos = []
        p = cls.P_CLS.new_message()
        flat = []
        for type_, pcbs in pcb_dict.items():
            for pcb in pcbs:
                flat.append((type_, pcb))
        p.init("recs", len(flat))
        for i, (type_, pcb) in enumerate(flat):
            p.recs[i].type = type_
            p.recs[i].pathSeg = pcb.p
        p.init("revInfos", len(rev_infos))
        for i, rev_info in enumerate(rev_infos):
            p.revInfos[i] = rev_info.p
        return cls(p)

    def iter_pcbs(self):
        for rec in self.p.recs:
            yield rec.type, PathSegment(rec.pathSeg)

    def rev_info(self, idx):
        return RevocationInfo(self.p.revInfos[idx])

    def iter_rev_infos(self, start=0):
        for i in range(start, len(self.p.revInfos)):
            yield self.rev_info(i)

    def num_segs(self):
        """Returns the total number of path segments."""
        return len(self.p.recs)

    def __str__(self):
        s = []
        s.append("%s:" % self.NAME)
        recs = list(self.iter_pcbs())
        recs.sort(key=lambda x: x[0])
        last_type = None
        for type_, pcb in recs:
            if type_ != last_type:
                s.append("  %s:" % PST.to_str(type_))
            s.append("    %s" % pcb.short_desc())
        for rev_info in self.iter_rev_infos():
            s.append("  %s" % rev_info.short_desc())

        return "\n".join(s)


class PathRecordsReg(PathSegmentRecords):
    NAME = "PathRecordsReg"


class PathRecordsSync(PathSegmentRecords):
    NAME = "PathRecordsSync"
