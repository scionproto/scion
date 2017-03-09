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
:mod:`drkey_mgmt` --- SCION DRKey management packets
=====================================================
"""
# External

# SCION
import proto.drkey_mgmt_capnp as P
from lib.crypto.certificate_chain import CertificateChain
from lib.errors import SCIONParseError
from lib.packet.host_addr import haddr_parse
from lib.packet.packet_base import Cerealizable, SCIONPayloadBaseProto
from lib.packet.scion_addr import ISD_AS
from lib.types import DRKeyMgmtType, PayloadClass


class DRKeyMgmtBase(SCIONPayloadBaseProto):
    PAYLOAD_CLASS = PayloadClass.DRKEY

    def _pack_full(self, p):
        wrapper = P.DRKeyMgmt.new_message(**{self.PAYLOAD_TYPE: p})
        return super()._pack_full(wrapper)


class DRKeyRequest(DRKeyMgmtBase):
    NAME = "DRKeyRequest"
    PAYLOAD_TYPE = DRKeyMgmtType.FIRST_ORDER_REQUEST
    P_CLS = P.DRKeyReq

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)
        self.chain = CertificateChain.from_raw(p.chain, lz4_=True)

    @classmethod
    def from_values(cls, prefetch, isd_as, timestamp, signature, chain):
        return cls(cls.P_CLS.new_message(
            prefetch=prefetch, isdas=isd_as.int(), timestamp=timestamp,
            signature=signature, chain=chain.pack(lz4_=True)))

    def short_desc(self):
        return "%s" % self.isd_as

    def __str__(self):
        return ("%s: ISD-AS: %s Timestamp: %s Prefetch: %s" %
                (self.NAME, self.isd_as, self.p.timestamp, self.p.prefetch))


class DRKeyReply(DRKeyMgmtBase):
    NAME = "DRKeyReply"
    PAYLOAD_TYPE = DRKeyMgmtType.FIRST_ORDER_REPLY
    P_CLS = P.DRKeyRep

    def __init__(self, p):
        super().__init__(p)
        self.isd_as = ISD_AS(p.isdas)
        self.chain = CertificateChain.from_raw(p.chain, lz4_=True)

    @classmethod
    def from_values(cls, prefetch, isd_as, timestamp, cipher, signature, chain):
        return cls(cls.P_CLS.new_message(
            prefetch=prefetch, isdas=isd_as.int(), timestamp=timestamp,
            cipher=cipher, signature=signature, chain=chain.pack(lz4_=True)))

    def short_desc(self):
        return "%s" % self.isd_as

    def __str__(self):
        return "%s: ISD-AS: %s Timestamp: %s Prefetch: %s" % (
            self.NAME, self.isd_as, self.p.timestamp, self.p.prefetch)


class DRKeyProtocolRequest(DRKeyMgmtBase):
    NAME = "DRKeyProtocolRequest"
    PAYLOAD_TYPE = DRKeyMgmtType.PROTOCOL_REQUEST
    P_CLS = P.DRKeyProtoReq

    @classmethod
    def from_values(cls, timestamp, cipher, signature):
        return cls(cls.P_CLS.new_message(timestamp=timestamp, cipher=cipher,
                                         signature=signature))

    def short_desc(self):
        return self.NAME

    def __str__(self):
        return self.NAME

    class Request(Cerealizable):
        NAME = "DRKeyProtocolRequest.Request"
        P_CLS = P.DRKeyProtocolRequest

        def _parse_host(self, union):
            if union.which() == "holder":
                return haddr_parse(union.holder.type, union.holder.host)
            return None

        def __init__(self, p):
            super().__init__(p)

            self.src_ia = ISD_AS(p.srcIA)
            self.dst_ia = ISD_AS(p.dstIA)
            if p.addIA.which() == "ia":
                self.add_ia = ISD_AS(p.addIA.ia)
            else:
                self.add_ia = None
            self.src_host = self._parse_host(p.srcHost)
            self.dst_host = self._parse_host(p.dstHost)
            self.add_host = self._parse_host(p.addHost)

        @classmethod
        def from_values(cls, params):  # pragma: no cover
            proto = cls.P_CLS.new_message(
                reqCode=params.request_code, srcIA=params.src_ia.pack(),
                dstIA=params.dst_ia.pack(), protocol=params.protocol,
                reqID=params.request_id)
            if params.add_ia:
                proto.addIA.ia = params.add_ia.pack()
            if params.src_host:
                proto.srcHost.holder = P.DRKeyHostHolder.new_message(
                    type=params.src_host.TYPE, host=params.src_host.pack())
            if params.dst_host:
                proto.dstHost.holder = P.DRKeyHostHolder.new_message(
                    type=params.dst_host.TYPE, host=params.dst_host.pack())
            if params.add_host:
                proto.addHost.holder = P.DRKeyHostHolder.new_message(
                    type=params.add_host.TYPE, host=params.add_host.pack())
            return cls(proto)

        def short_desc(self):
            return "ID: %s ReqCode: %s Src (%s,%s) Dst: (%s,%s) Add: (%s,%s)" % (
                self.p.reqID, self.p.reqCode, self.src_ia, self.src_host,
                self.dst_ia, self.dst_host, self.add_ia, self.dst_host)

        class Params(object):
            request_code = None
            request_id = None
            protocol = None
            src_ia = None
            dst_ia = None
            add_ia = None
            src_host = None
            dst_host = None
            add_host = None


class DRKeyProtocolReply(DRKeyMgmtBase):
    NAME = "DRKeyProtocolReply"
    PAYLOAD_TYPE = DRKeyMgmtType.PROTOCOL_REPLY
    P_CLS = P.DRKeyProtoRep

    @classmethod
    def from_values(cls, timestamp, cipher, signature):
        return cls(cls.P_CLS.new_message(timestamp=timestamp, cipher=cipher,
                                         signature=signature))

    def short_desc(self):
        return self.NAME

    def __str__(self):
        return self.NAME

    class Reply(Cerealizable):
        NAME = "DRKeyProtocolReply.Reply"
        P_CLS = P.DRKeyProtocolReply

        @classmethod
        def from_values(cls, req_id, drkey, exp_time):   # pragma: no cover
            return cls(cls.P_CLS.new_message(reqID=req_id, drkey=drkey,
                                             expTime=exp_time))

        def short_desc(self):
            return "ID: %s expTime: %s" % (self.p.reqID, self.p.expTime)


def parse_drkeymgmt_payload(wrapper):  # pragma: no cover
    type_ = wrapper.which()
    for c in (DRKeyRequest, DRKeyReply, DRKeyProtocolRequest,
              DRKeyProtocolReply):
        if c.PAYLOAD_TYPE == type_:
            return c(getattr(wrapper, type_))
    raise SCIONParseError("Unsupported DRKey management type: %s" % type_)
