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
import struct

# External
import capnp  # noqa
from Crypto.Hash import SHA256

# SCION
import proto.path_mgmt_capnp as P
from lib.packet.path_mgmt.base import PathMgmtPayloadBase
from lib.packet.pcb import PathSegment
from lib.types import PathMgmtType as PMT, PathSegmentType as PST


class PathSegmentRecords(PathMgmtPayloadBase):  # pragma: no cover
    """
    Path Record class used for sending list of down/up-paths. Paths are
    represented as objects of the PathSegment class.
    """
    P_CLS = P.SegRecs

    def __init__(self, p):  # pragma: no cover
        super().__init__(p)

    def iter_pcbs(self):
        for rec in self.p.recs:
            yield rec.type, PathSegment(rec.pcb)

    @classmethod
    def from_values(cls, pcb_dict):
        """
        :param pcb_dict: dict of {seg_type: [pcbs]}
        """
        p = cls.P_CLS.new_message()
        flat = []
        for type_, pcbs in pcb_dict.items():
            for pcb in pcbs:
                flat.append((type_, pcb))
        p.init("recs", len(flat))
        for i, (type_, pcb) in enumerate(flat):
            p.recs[i].type = type_
            p.recs[i].pcb = pcb.p
        return cls(p)

    def get_trcs_certs(self):
        """
        Returns a dict of all trcs' versions and a dict of all certificates'
        versions used in this reply, with their highest version number.
        """
        trcs = {}
        certs = {}
        for pcb in self.iter_pcbs():
            trcs_, certs_ = pcb[1].get_trcs_certs()
            for isd in trcs_:
                if isd in trcs:
                    trcs[isd].update(trcs_[isd])
                else:
                    trcs[isd] = trcs_[isd]
            for isd_as in certs_:
                if isd_as in certs:
                    certs[isd_as].update(certs_[isd_as])
                else:
                    certs[isd_as] = certs_[isd_as]
        return trcs, certs

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
        return "\n".join(s)

    def _get_pcbs_hash(self):
        h = SHA256.new()
        for pcb in self.iter_pcbs():
            h.update(struct.pack("!q", hash(pcb[1])))
        return h.digest

    def __hash__(self):
        return hash(self._get_pcbs_hash())

    def __eq__(self, other):
        return self.__str__ == str(other)


class PathRecordsReply(PathSegmentRecords):
    NAME = "PathRecordsReply"
    PAYLOAD_TYPE = PMT.REPLY


class PathRecordsReg(PathSegmentRecords):
    NAME = "PathRecordsReg"
    PAYLOAD_TYPE = PMT.REG


class PathRecordsSync(PathSegmentRecords):
    NAME = "PathRecordsSync"
    PAYLOAD_TYPE = PMT.SYNC
