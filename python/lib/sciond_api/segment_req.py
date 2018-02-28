# Copyright 2018 ETH Zurich
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
:mod:`segment_req` --- SCIOND segments by type requests and replies
====================================================
"""
# External
import capnp  # noqa
from datetime import timedelta

# SCION
import proto.sciond_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.sciond_api.path_meta import PathInterface
from lib.util import iso_timestamp


class SCIONDSegTypeHopRequest(Cerealizable):
    NAME = "SCIONDSegTypeHopRequest"
    P_CLS = P.SegTypeHopReq

    @classmethod
    def from_values(cls, seg_type):
        p = cls.P_CLS.new_message(type=seg_type)
        return cls(p)

    def short_desc(self):
        return "%s: type: %s" % (self.NAME, self.p.type)


class SCIONDSegTypeHopReply(Cerealizable):
    NAME = "SCIONDSegTypeHopReply"
    P_CLS = P.SegTypeHopReply

    @classmethod
    def from_values(cls, entries):
        p = cls.P_CLS.new_message()
        entry_list = p.init("entries", len(entries))
        for i, entry in enumerate(entries):
            entry_list[i] = entry.p
        return cls(p)

    def entry(self, idx):
        return SCIONDSegTypeHopReplyEntry(self.p.entries[idx])

    def iter_entries(self):
        for entry in self.p.entries:
            yield SCIONDSegTypeHopReplyEntry(entry)

    def short_desc(self):
        return "\n".join([entry.short_desc() for entry in self.iter_entries()])


class SCIONDSegTypeHopReplyEntry(Cerealizable):
    NAME = "SCIONDSegTypeHopReplyEntry"
    P_CLS = P.SegTypeHopReplyEntry

    @classmethod
    def from_values(cls, interfaces, timestamp, expTime):
        p = cls.P_CLS.new_message(timestamp=timestamp, expTime=expTime)
        ifs = p.init("interfaces", len(interfaces))
        for i, if_ in enumerate(interfaces):
            ifs[i] = if_.p
        return cls(p)

    def iter_ifs(self):
        for if_ in self.p.interfaces:
            yield PathInterface(if_)

    def short_desc(self):
        desc = []
        remain = self.p.expTime - self.p.timestamp
        desc.append("%s, %s, " % (iso_timestamp(
            self.p.timestamp), timedelta(seconds=remain)))
        desc.append(", ".join([if_.short_desc() for if_ in self.iter_ifs()]))
        return "".join(desc)

    def __str__(self):
        desc = ["%s:" % self.NAME]
        if_str = ", ".join([if_.short_desc() for if_ in self.iter_ifs()])
        desc.append("  Interfaces: %s " % if_str)
        desc.append("  Timestamp: %s" % self.p.timestamp)
        desc.append("  Expiration: %s" % self.p.expTime)
        return "\n".join(desc)
