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
from lib.sciond_api.base import SCIONDMsgBase
from lib.types import SCIONDMsgType as SMT


class SCIONDASInfoRequest(SCIONDMsgBase):
    NAME = "ASInfoRequest"
    MSG_TYPE = SMT.AS_REQUEST
    P_CLS = P.ASInfoReq

    @classmethod
    def from_values(cls, id_):
        p = cls.P_CLS.new_message()
        return cls(p, id_)

    def short_desc(self):
        return self.NAME


class SCIONDASInfoReply(SCIONDMsgBase):
    NAME = "ASInfoReply"
    MSG_TYPE = SMT.AS_REPLY
    P_CLS = P.ASInfoReply

    @classmethod
    def from_values(cls, id_, entries):
        p = cls.P_CLS.new_message()
        entry_list = p.init("entries", len(entries))
        for i, entry in enumerate(entries):
            entry_list[i] = entry.p
        return cls(p, id_)

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
    def from_values(cls, isd_as, mtu, is_core):
        p = cls.P_CLS.new_message(isdas=int(isd_as), mtu=mtu, isCore=is_core)
        return cls(p)

    def isd_as(self):
        return ISD_AS(self.p.isdas)

    def short_desc(self):
        return "id=%s mtu=%d is_core=%s" % (
            self.isd_as(), self.p.mtu, self.p.isCore)
