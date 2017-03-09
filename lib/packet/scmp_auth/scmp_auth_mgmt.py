# Copyright 2015 ETH Zurich
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
:mod:`scmp_auth_mgmt` --- SCION SCMPAuth DRKey managment packets
=====================================================
"""
# External
import capnp  # noqa

# SCION
import proto.scmp_auth_mgmt_capnp as P
from lib.crypto.certificate_chain import CertificateChain
from lib.errors import SCIONParseError
from lib.packet.packet_base import SCIONPayloadBaseProto
from lib.packet.scion_addr import ISD_AS
from lib.types import PayloadClass, SCMPAuthMgmtType


class SCMPAuthMgmtBase(SCIONPayloadBaseProto):  # pragma: no cover
    PAYLOAD_CLASS = PayloadClass.SCMP_AUTH

    def _pack_full(self, p):
        wrapper = P.SCMPAuthMgmt.new_message(**{self.PAYLOAD_TYPE: p})
        return super()._pack_full(wrapper)


class SCMPAuthRemoteDRKeyRequest(SCMPAuthMgmtBase):  # pragma: no cover
    NAME = "SCMPAuthDRKeyRequest"
    PAYLOAD_TYPE = SCMPAuthMgmtType.SCMP_AUTH_REMOTE_REQUEST
    P_CLS = P.ScmpAuthRemoteReq

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)
        self.timestamp = p.timestamp
        self.signature = p.signature
        self.chain = CertificateChain.from_raw(p.chain, lz4_=True)

    @classmethod
    def from_values(cls, isd_as, timestamp, signature, chain):
        return cls(cls.P_CLS.new_message(isdas=int(isd_as), timestamp=timestamp, signature=signature, chain=chain.pack(lz4_=True)))

    def short_desc(self):
        return "%s" % self.isd_as

    def __str__(self):
        return "%s: ISD-AS: %s Timestamp: %s" % (self.NAME, self.isd_as, self.timestamp)


class SCMPAuthRemoteDRKeyReply(SCMPAuthMgmtBase):  # pragma: no cover
    NAME = "SCMPAuthDRKeyReply"
    PAYLOAD_TYPE = SCMPAuthMgmtType.SCMP_AUTH_REMOTE_REPLY
    P_CLS = P.ScmpAuthRemoteRep

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)
        self.timestamp = p.timestamp
        self.cipher = p.cipher
        self.signature = p.signature
        self.chain = CertificateChain.from_raw(p.chain, lz4_=True)

    @classmethod
    def from_values(cls, isd_as, timestamp, cipher, signature, chain):
        return cls(cls.P_CLS.new_message(isdas=int(isd_as), timestamp=timestamp, cipher=cipher, signature=signature, chain=chain.pack(lz4_=True)))

    def short_desc(self):
        return "%s" % self.isd_as

    def __str__(self):
        return "%s: ISD-AS: %s Timestamp: %s" % (self.NAME, self.isd_as, self.timestamp)

class SCMPAuthLocalDRKeyRequest(SCMPAuthMgmtBase):  # pragma: no cover
    NAME = "SCMPAuthDRKeyRequest"
    PAYLOAD_TYPE = SCMPAuthMgmtType.SCMP_AUTH_LOCAL_REQUEST
    P_CLS = P.ScmpAuthLocalReq

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)

    @classmethod
    def from_values(cls, isd_as):
        return cls(cls.P_CLS.new_message(isdas=int(isd_as)))

    def short_desc(self):
        return "%s" % self.isd_as

    def __str__(self):
        return "%s: ISD-AS: %s" % (self.NAME, self.isd_as)


class SCMPAuthLocalDRKeyReply(SCMPAuthMgmtBase):  # pragma: no cover
    NAME = "SCMPAuthDRKeyReply"
    PAYLOAD_TYPE = SCMPAuthMgmtType.SCMP_AUTH_LOCAL_REPLY
    P_CLS = P.ScmpAuthLocalRep

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)
        self.cipher = p.cipher

    @classmethod
    def from_values(cls, isd_as, cipher):
        return cls(cls.P_CLS.new_message(isdas=int(isd_as), cipher=cipher))

    def short_desc(self):
        return "%s" % self.isd_as

    def __str__(self):
        return "%s: ISD-AS: %s" % (self.NAME, self.isd_as)


def parse_scmpauthmgmt_payload(wrapper):  # pragma: no cover
    type_ = wrapper.which()
    for c in SCMPAuthRemoteDRKeyRequest, SCMPAuthRemoteDRKeyReply, SCMPAuthLocalDRKeyRequest, SCMPAuthLocalDRKeyReply:
        if c.PAYLOAD_TYPE == type_:
            return c(getattr(wrapper, type_))
    raise SCIONParseError("Unsupported scmp auth management type: %s" % type_)
