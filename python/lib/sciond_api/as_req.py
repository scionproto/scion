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
:mod:`as_req` --- SCIOND ISD-AS requests and replies
====================================================
"""
# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS


class SCIONDASInfoRequest(Cerealizable):
    NAME = "SCIONDASInfoRequest"
    P_CLS = P.ASInfoReq

    @classmethod
    def from_values(cls, isd_as=None):
        p = cls.P_CLS.new_message()
        if isd_as:
            p.isdas = isd_as.int()
        return cls(p)

    def isd_as(self):
        if self.p.isdas:
            return ISD_AS(self.p.isdas)
        return None

    def short_desc(self):
        return "ISD_AS: %s" % (self.isd_as() or "local")


class SCIONDASInfoReply(Cerealizable):
    NAME = "ASInfoReply"
    P_CLS = P.ASInfoReply

    @classmethod
    def from_values(cls, entries):
        p = cls.P_CLS.new_message()
        entry_list = p.init("entries", len(entries))
        for i, entry in enumerate(entries):
            entry_list[i] = entry.p
        return cls(p)

    def entry(self, idx):
        return SCIONDASInfoReplyEntry(self.p.entries[idx])

    def iter_entries(self):
        for entry in self.p.entries:
            yield SCIONDASInfoReplyEntry(entry)

    def short_desc(self):
        return "\n".join([entry.short_desc() for entry in self.iter_entries()])


class SCIONDASInfoReplyEntry(Cerealizable):
    NAME = "ASInfoReplyEntry"
    P_CLS = P.ASInfoReplyEntry

    @classmethod
    def from_values(cls, isd_as, is_core, mtu=None):
        p = cls.P_CLS.new_message(isdas=int(isd_as), isCore=is_core)
        if mtu:
            p.mtu = mtu
        return cls(p)

    def isd_as(self):
        return ISD_AS(self.p.isdas)

    def short_desc(self):
        return "id=%s is_core=%s mtu=%s" % (
            self.isd_as(), self.p.isCore, self.p.mtu or "unknown")
