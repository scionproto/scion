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
:mod:`cert_mgmt` --- SCION cert/trc managment packets
=====================================================
"""
# External
import capnp
import lz4

# SCION
from lib.crypto.certificate import CertificateChain, TRC
from lib.errors import SCIONParseError
from lib.packet.packet_base import SCIONPayloadBaseProto
from lib.packet.scion_addr import ISD_AS
from lib.types import CertMgmtType, PayloadClass


class CertMgmtBase(SCIONPayloadBaseProto):
    PAYLOAD_CLASS = PayloadClass.CERT


class CertMgmtRequest(CertMgmtBase):  # pragma: no cover
    def isd_as(self):
        return ISD_AS(self.p.isdas)

    @classmethod
    def from_values(cls, isd_as, version):
        return cls(cls.P_CLS.new_message(isdas=str(isd_as), version=version))


class CertChainRequest(CertMgmtRequest):
    NAME = "CertChainRequest"
    PAYLOAD_TYPE = CertMgmtType.CERT_CHAIN_REQ
    P = capnp.load("proto/cert_req.capnp")
    P_CLS = P.CertReq

    def short_desc(self):
        return "%sv%s" % (self.isd_as(), self.p.version)


class CertChainReply(CertMgmtBase):  # pragma: no cover
    NAME = "CertChainReply"
    PAYLOAD_TYPE = CertMgmtType.CERT_CHAIN_REPLY
    P = capnp.load("proto/cert_reply.capnp")
    P_CLS = P.CertRep

    def __init__(self, p):
        super().__init__(p)
        text = lz4.loads(p.chain).decode('utf-8')
        self.chain = CertificateChain(text)

    @classmethod
    def from_values(cls, chain):
        data = lz4.dumps(chain.pack())
        return cls(cls.P_CLS.new_message(chain=data))

    def short_desc(self):
        return "%sv%s" % self.chain.get_leaf_isd_as_ver()

    def __str__(self):
        isd_as, ver = self.chain.get_leaf_isd_as_ver()
        return "%s: ISD-AS: %s Version: %s" % (self.NAME, isd_as, ver)


class TRCRequest(CertMgmtRequest):
    NAME = "TRCRequest"
    PAYLOAD_TYPE = CertMgmtType.TRC_REQ
    P = capnp.load("proto/trc_req.capnp")
    P_CLS = P.TRCReq

    def short_desc(self):
        return "%sv%s" % (self.isd_as()[0], self.p.version)


class TRCReply(CertMgmtBase):  # pragma: no cover
    NAME = "TRCReply"
    PAYLOAD_TYPE = CertMgmtType.TRC_REPLY
    P = capnp.load("proto/trc_reply.capnp")
    P_CLS = P.TRCRep

    def __init__(self, p):
        super().__init__(p)
        text = lz4.loads(p.trc).decode('utf-8')
        self.trc = TRC(text)

    @classmethod
    def from_values(cls, trc):
        data = lz4.dumps(trc.pack())
        return cls(cls.P_CLS.new_message(trc=data))

    def short_desc(self):
        return "%sv%s" % self.trc.get_isd_ver()

    def __str__(self):
        isd, ver = self.trc.get_isd_ver()
        return "%s: ISD: %s version: %s TRC: %s" % (
            self.NAME, isd, ver, self.trc)


_TYPE_MAP = {
    CertMgmtType.CERT_CHAIN_REQ: CertChainRequest,
    CertMgmtType.CERT_CHAIN_REPLY: CertChainReply,
    CertMgmtType.TRC_REQ: TRCRequest,
    CertMgmtType.TRC_REPLY: TRCReply,
}


def parse_certmgmt_payload(type_, data):  # pragma: no cover
    if type_ not in _TYPE_MAP:
        raise SCIONParseError("Unsupported cert management type: %s" % type_)
    cls_ = _TYPE_MAP[type_]
    return cls_.from_raw(data.pop())
