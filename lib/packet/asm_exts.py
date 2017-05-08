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
from lib.errors import SCIONSigVerError
from lib.packet.packet_base import Cerealizable
from lib.types import ASMExtType


class RoutingPolicyExt(Cerealizable):
    NAME = "PolicyExt"
    P_CLS = P.RoutingPolicyExt
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, ext_type, type_, if_, isd_ases):
        p = cls.P_CLS.new_message(extType=ext_type, polType=type_, itf=if_)
        p.init("isdases", len(isd_ases))
        for i, isd_as in enumerate(isd_ases):
            p.isdases[i] = int(isd_as)
        cls.extType = ASMExtType.ROUTING_POLICY
        return cls(p)

    def sig_pack3(self):
        """
        Pack for signing version 3 (defined by highest field number).
        """
        b = []
        if self.VER != 3:
            raise SCIONSigVerError(
                "RoutingPolicyExt.sig_pack4 cannot support version %s", self.VER)
        b.append(self.p.extType.to_bytes(1, 'big'))
        b.append(self.p.polType.to_bytes(1, 'big'))
        b.append(self.p.itf.to_bytes(2, 'big'))
        for isd_as in self.p.isdases:
            b.append(isd_as.to_bytes(4, 'big'))
        return b"".join(b)

    def short_desc(self):
        a = []
        a.append("RoutingPolicyExt extension: Policy type: %s, Interface: %s" %
                 (self.p.extType, self.p.itf))
        for isd_as in self.p.isdases:
            a.append(" %s" % isd_as)
        return "\n".join(a)
