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
from lib.packet.scion_addr import ISD_AS
from lib.types import RoutingPolType


class ASMExt(Cerealizable):
    NAME = "ASMExt"
    P_CLS = P.ASMExt
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, routingPolicy=None):
        p = cls.P_CLS.new_message()
        if routingPolicy:
            p.extension.routingPolicy = routingPolicy.p
        return cls(p)

    def routing_pol_ext(self):
        return RoutingPolicyExt(self.p.extension.routingPolicy)

    def sig_pack0(self):
        """
        Pack for signing version 0 (defined by highest field number).
        """
        b = []
        if self.VER != 0:
            raise SCIONSigVerError(
                "ASMExt.sig_pack0 cannot support version %s", self.VER)
        if self.p.extension.which() == 'routingPolicy':
            b.append(self.routing_pol_ext().sig_pack2())
        return b"".join(b)


class RoutingPolicyExt(Cerealizable):
    NAME = "RoutingPolicyExt"
    P_CLS = P.RoutingPolicyExt
    VER = len(P_CLS.schema.fields) - 1

    @classmethod
    def from_values(cls, type_, if_, isd_ases):
        p = cls.P_CLS.new_message(polType=type_, ifID=if_)
        p.init("isdases", len(isd_ases))
        for i, isd_as in enumerate(isd_ases):
            p.isdases[i] = int(isd_as)
        return cls(p)

    def sig_pack2(self):
        """
        Pack for signing version 2 (defined by highest field number).
        """
        b = []
        if self.VER != 2:
            raise SCIONSigVerError("RoutingPolicyExt.sig_pack2 cannot support version %s", self.VER)
        b.append(self.p.polType.to_bytes(1, 'big'))
        b.append(self.p.ifID.to_bytes(2, 'big'))
        for isd_as in self.p.isdases:
            b.append(isd_as.to_bytes(4, 'big'))
        return b"".join(b)

    def short_desc(self):
        a = []
        a.append("RoutingPolicyExt extension: Policy type: %s, Interface: %s, ASes:" %
                 (RoutingPolType.to_str(self.p.polType), self.p.ifID))
        for isd_as in self.p.isdases:
            a.append(" %s" % ISD_AS(isd_as))
        return "\n".join(a)
