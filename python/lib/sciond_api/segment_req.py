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

# SCION
import proto.sciond_capnp as P
from lib.packet.packet_base import Cerealizable


class SCIONDSegTypeRequest(Cerealizable):
    NAME = "SCIONDSegTypeRequest"
    P_CLS = P.SegTypeReq

    @classmethod
    def from_values(cls, seg_type):
        p = cls.P_CLS.new_message(type=seg_type)
        return cls(p)

    def short_desc(self):
        return "%s: type: %s" % (self.NAME, self.p.type)


class SCIONDSegTypeReply(Cerealizable):
    NAME = "SCIONDSegTypeReply"
    P_CLS = P.SegTypeReply

    @classmethod
    def from_values(cls, entries):
        p = cls.P_CLS.new_message(entries=entries)
        return cls(p)

    def entry(self, idx):
        return self.p.entries[idx]

    def iter_entries(self):
        for entry in self.p.entries:
            yield entry

    def short_desc(self):
        return "\n".join([entry.short_desc() for entry in self.iter_entries()])
