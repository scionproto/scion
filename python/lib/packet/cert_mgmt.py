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
import capnp  # noqa

# SCION
import proto.cert_mgmt_capnp as P
from lib.crypto.certificate_chain import CertificateChain
from lib.crypto.trc import TRC
from lib.packet.packet_base import CerealBox, Cerealizable
from lib.packet.scion_addr import ISD_AS
from lib.types import CertMgmtType


class CertMgmt(CerealBox):  # pragma: no cover
    NAME = "CertMgmt"
    P_CLS = P.CertMgmt
    # Set at end of file, after classes have been defined.
    CLASS_FIELD_MAP = None


class CertMgmtRequest(Cerealizable):  # pragma: no cover
    def isd_as(self):
        return ISD_AS(self.p.isdas)

    @classmethod
    def from_values(cls, isd_as, version, cache_only=False):
        return cls(cls.P_CLS.new_message(isdas=int(isd_as), version=version,
                                         cacheOnly=cache_only))


class CertChainRequest(CertMgmtRequest):
    NAME = "CertChainRequest"
    P_CLS = P.CertChainReq

    def short_desc(self):
        return "%sv%s (Cache only? %s)" % (self.isd_as(), self.p.version,
                                           self.p.cacheOnly)


class CertChainReply(Cerealizable):  # pragma: no cover
    NAME = "CertChainReply"
    P_CLS = P.CertChainRep

    def __init__(self, p):
        super().__init__(p)
        self.chain = CertificateChain.from_raw(p.chain, lz4_=True)

    @classmethod
    def from_values(cls, chain):
        return cls(cls.P_CLS.new_message(chain=chain.pack(lz4_=True)))

    def short_desc(self):
        return "%sv%s" % self.chain.get_leaf_isd_as_ver()

    def __str__(self):
        isd_as, ver = self.chain.get_leaf_isd_as_ver()
        return "%s: ISD-AS: %s Version: %s" % (self.NAME, isd_as, ver)


class TRCRequest(CertMgmtRequest):
    NAME = "TRCRequest"
    P_CLS = P.TRCReq

    def short_desc(self):
        return "%sv%s (Cache only? %s)" % (self.isd_as()[0], self.p.version,
                                           self.p.cacheOnly)


class TRCReply(Cerealizable):  # pragma: no cover
    NAME = "TRCReply"
    P_CLS = P.TRCRep

    def __init__(self, p):
        super().__init__(p)
        self.trc = TRC.from_raw(p.trc, lz4_=True)

    @classmethod
    def from_values(cls, trc):
        return cls(cls.P_CLS.new_message(trc=trc.pack(lz4_=True)))

    def short_desc(self):
        return "%sv%s" % self.trc.get_isd_ver()

    def __str__(self):
        isd, ver = self.trc.get_isd_ver()
        return "%s: ISD: %s version: %s TRC: %s" % (
            self.NAME, isd, ver, self.trc)


CertMgmt.CLASS_FIELD_MAP = {
    CertChainRequest: CertMgmtType.CERT_CHAIN_REQ,
    CertChainReply: CertMgmtType.CERT_CHAIN_REPLY,
    TRCRequest: CertMgmtType.TRC_REQ,
    TRCReply: CertMgmtType.TRC_REPLY,
}
