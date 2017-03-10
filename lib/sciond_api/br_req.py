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
:mod:`br_req` --- SCIOND BR requests and replies
================================================
"""
# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.sciond_api.base import SCIONDMsgBase
from lib.sciond_api.host_info import HostInfo
from lib.types import SCIONDMsgType as SMT


class SCIONDBRInfoRequest(SCIONDMsgBase):
    NAME = "BRInfoRequest"
    MSG_TYPE = SMT.BR_REQUEST
    P_CLS = P.BRInfoRequest

    @classmethod
    def from_values(cls, ids=None):
        """
        Creates an SCIONDBRInfoRequest.

        :param ids: List of interface ids. An empty list means all interfaces of
            all BRs.
        """
        p = cls.P_CLS.new_message()
        if ids:
            id_entries = p.init("ifIDs", len(ids))
            for i, if_id in enumerate(ids):
                id_entries[i] = if_id
        return cls(p)

    def all_brs(self):
        return not self.p.ifIDs

    def iter_ids(self):
        for if_id in self.p.ifIDs:
            yield if_id

    def short_desc(self):
        if_str = "ALL" if self.all_brs() else str(self.p.ifIDs)
        return "IF IDs: %s" % if_str


class SCIONDBRInfoReply(SCIONDMsgBase):
    NAME = "BRInfoReply"
    MSG_TYPE = SMT.BR_REPLY
    P_CLS = P.BRInfoReply

    @classmethod
    def from_values(cls, entries):
        p = cls.P_CLS.new_message()
        entry_list = p.init("entries", len(entries))
        for i, entry in enumerate(entries):
            entry_list[i] = entry.p
        return cls(p)

    def entry(self, idx):
        return SCIONDBRInfoReplyEntry(self.p.entries[idx])

    def iter_entries(self):
        for entry in self.p.entries:
            yield SCIONDBRInfoReplyEntry(entry)

    def short_desc(self):
        return "\n".join([entry.short_desc() for entry in self.iter_entries()])


class SCIONDBRInfoReplyEntry(Cerealizable):
    NAME = "BRInfoReplyEntry"
    P_CLS = P.BRInfoReplyEntry

    @classmethod
    def from_values(cls, if_id, host_info):
        p = cls.P_CLS.new_message(ifID=if_id, hostInfo=host_info.p)
        return cls(p)

    def host_info(self):
        return HostInfo(self.p.hostInfo)

    def short_desc(self):
        return "IF ID: %d Host Info: %s" % (
            self.p.ifID, self.host_info().short_desc())
