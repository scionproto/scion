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
from lib.packet.scion_addr import ISD_AS
from lib.sciond_api.base import SCIONDMsgBase
from lib.types import SCIONDMsgType as SMT


class SCIONDASRequest(SCIONDMsgBase):
    """ISD-AS request"""
    NAME = "ASRequest"
    MSG_TYPE = SMT.AS_REQUEST
    P_CLS = P.ASReq

    @classmethod
    def from_values(cls):
        p = cls.P_CLS.new_message()
        return cls(p)

    def short_desc(self):
        return self.NAME


class SCIONDASReply(SCIONDMsgBase):
    """ISD-AS reply."""
    NAME = "ASReply"
    MSG_TYPE = SMT.AS_REPLY
    P_CLS = P.ASReply

    @classmethod
    def from_values(cls, ases):
        p = cls.P_CLS.new_message()
        as_list = p.init("ases", len(ases))
        for i, isd_as in enumerate(ases):
            as_list[i] = int(isd_as)
        return cls(p)

    def iter_ases(self):
        for isd_as in self.p.ases:
            yield ISD_AS(isd_as)

    def short_desc(self):
        return "%s: %s" % (
            self.NAME, ", ".join(str(isd_as) for isd_as in self.iter_ases()))
