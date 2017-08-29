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
:mod:`set_info` --- Hidden PCB set info payload
===============================================
"""
# Stdlib
import logging
# External
import capnp  # noqa

# SCION
import proto.set_info_capnp as P
from lib.packet.path_mgmt.base import PathMgmtPayloadBase
from lib.packet.scion_addr import ISD_AS
from lib.types import PathMgmtType as PMT


class PCBSetInfo(PathMgmtPayloadBase):
    """
    Class containing revocation information, i.e., the revocation token.
    """
    NAME = "HiddenPCBSetInfo"
    PAYLOAD_TYPE = PMT.REGSET
    P_CLS = P.SetInfo

    @classmethod
    def from_values(cls, set_id, hps_ia, member_ias):
        """
        Returns a PCBSetInfo object with the specified values.

        :param str set_id: ID of the PCB-Set
        :param ISD_AS hps_ia: The ISD_AS of the hidden path server.
        :param list member_ias: A list that contains the ISD_AS of members
        """
        p = cls.P_CLS.new_message(setID=set_id, hpsIA=int(hps_ia))
        members = p.init('memberIAs', len(member_ias))
        for i, member_ia in enumerate(member_ias):
            members[i] = int(member_ia)
        return cls(p)

    def set_id(self):
        return self.p.setID.decode('utf-8')

    def hps_ia(self):
        return ISD_AS(self.p.hpsIA)

    def member_ia(self, idx):
        return ISD_AS(self.p.memberIAs[idx])

    def iter_member_ias(self, start=0):
        for i in range(start, len(self.p.memberIAs)):
            yield self.member_ia(i)

    def cmp_str(self):
        b = []
        b.append(self.p.setID)
        b.append(self.p.hpsIA.to_bytes(4, 'big'))
        for member_ia in self.iter_member_ias():
            b.append(int(member_ia).to_bytes(4, 'big'))
        return b"".join(b)

    def __eq__(self, other):
        if other is None:
            logging.error("Other RevInfo object is None.")
            return False
        return self.cmp_str() == other.cmp_str()

    def __hash__(self):
        return hash(self.cmp_str())

    def short_desc(self):
        return "PCB-Set ID: %s Hidden Path Server: %s MemberIAs: %d ASes" %\
               (self.set_id(), self.hps_ia(), len(self.p.memberIAs))
