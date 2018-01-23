# Copyright 2017 ETH Zurich
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
:mod:`segment_req` --- SCIOND segment requests and replies
====================================================
"""
# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.packet.packet_base import Cerealizable


class SCIONDSegmentRequest(Cerealizable):
    NAME = "SCIONDSegmentRequest"
    P_CLS = P.SegmentReq

    @classmethod
    def from_values(cls, seg_type=None):
        p = cls.P_CLS.new_message()
        p.segmentType = seg_type
        return cls(p)

    def short_desc(self):
        desc = ["%s:" % self.NAME]
        desc.append("  segmentType: %s" % self.p.segmentType)
        return "\n".join(desc)


class SCIONDSegmentReply(Cerealizable):
    NAME = "SegmentReply"
    P_CLS = P.SegmentReply

    @classmethod
    def from_values(cls, entries):
        p = cls.P_CLS.new_message()
        entry_list = p.init("entries", len(entries))
        for i, entry in enumerate(entries):
            entry_list[i] = entry.p
        return cls(p)

    def entry(self, idx):
        return SCIONDSegmentReplyEntry(self.p.entries[idx])

    def iter_entries(self):
        for entry in self.p.entries:
            yield SCIONDSegmentReplyEntry(entry)

    def short_desc(self):
        return "\n".join([entry.short_desc() for entry in self.iter_entries()])


class SCIONDSegmentReplyEntry(Cerealizable):
    NAME = "SegmentReplyEntry"
    P_CLS = P.SegmentReplyEntry

    @classmethod
    def from_values(cls, segment):
        p = cls.P_CLS.new_message(segment=segment)
        return cls(p)

    def short_desc(self):
        desc = ["%s:" % self.NAME]
        desc.append("  segment: %s" % self.p.segment)
        return "\n".join(desc)
