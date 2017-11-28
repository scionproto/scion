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
:mod:`info` --- Extensions for AS Markings
==========================================
"""

# SCION
import proto.asm_exts_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS
from lib.types import ASMExtType, RoutingPolType


class RoutingPolicyExt(Cerealizable):
    NAME = "RoutingPolicyExt"
    EXT_TYPE = ASMExtType.ROUTING_POLICY
    P_CLS = P.RoutingPolicyExt

    @classmethod
    def from_values(cls, type_, if_, isd_ases):
        p = cls.P_CLS.new_message(set=True, polType=type_, ifID=if_)
        p.init("isdases", len(isd_ases))
        for i, isd_as in enumerate(isd_ases):
            p.isdases[i] = int(isd_as)
        return cls(p)

    def short_desc(self):
        a = []
        a.append("RoutingPolicyExt extension: Policy type: %s, Interface: %s, ASes:" %
                 (RoutingPolType.to_str(self.p.polType), self.p.ifID))
        for isd_as in self.p.isdases:
            a.append(" %s" % ISD_AS(isd_as))
        return "\n".join(a)
