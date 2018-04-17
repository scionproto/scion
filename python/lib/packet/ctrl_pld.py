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
:mod:`ctrl_pld` --- SCION control payload
=========================================
"""
# Stdlib
import random
import struct

# External
import capnp

# SCION
import proto.ctrl_pld_capnp as P
from lib.drkey.drkey_mgmt import DRKeyMgmt
from lib.errors import SCIONParseError
from lib.packet.cert_mgmt import CertMgmt
from lib.packet.ifid import IFIDPayload
from lib.packet.packet_base import CerealBox, Cerealizable
from lib.packet.path_mgmt.base import PathMgmt
from lib.packet.pcb import PCB
from lib.packet.proto_sign import ProtoSign, ProtoSignType
from lib.sibra.payload import SIBRAPayload
from lib.types import PayloadClass
from lib.util import Raw


class SignedCtrlPayload(Cerealizable):
    NAME = "SignedCtrlPayload"
    P_CLS = P.SignedCtrlPld

    def __init__(self, p):  # pragma: no cover
        super().__init__(p)
        self.psign = ProtoSign(self.p.sign)

    @classmethod
    def from_raw(cls, raw):
        data = Raw(raw, "%s.from_raw" % cls.NAME)
        plen = struct.unpack("!I", data.pop(4))[0]
        if len(data) != plen:
            raise SCIONParseError("Payload length mismatch. Expected: %s Actual: %s" %
                                  (plen, len(data)))
        try:
            p = cls.P_CLS.from_bytes_packed(data.pop()).as_builder()
        except capnp.lib.capnp.KjException as e:
            raise SCIONParseError("Unable to parse %s capnp message: %s" % (cls.NAME, e)) from None
        return cls.from_proto(p)

    @classmethod
    def from_values(cls, cpld_raw, sign=None):
        if not sign:
            sign = ProtoSign.from_values(ProtoSignType.NONE, b"")
        return cls(cls.P_CLS.new_message(blob=cpld_raw, sign=sign.p))

    def sign(self, key):
        return self.psign.sign(key, self.p.blob)

    def verify(self, key):
        return self.psign.verify(key, self.p.blob)

    def pack(self):  # pragma: no cover
        raw = self.proto().to_bytes_packed()
        return struct.pack("!I", len(raw)) + raw

    def pld(self):
        return CtrlPayload.from_raw(self.p.blob)


class CtrlPayload(CerealBox):
    NAME = "CtrlPayload"
    P_CLS = P.CtrlPld
    CLASS_FIELD_MAP = {
        PCB: PayloadClass.PCB,
        IFIDPayload: PayloadClass.IFID,
        CertMgmt: PayloadClass.CERT,
        PathMgmt: PayloadClass.PATH,
        SIBRAPayload: PayloadClass.SIBRA,
        DRKeyMgmt: PayloadClass.DRKEY,
    }

    def __init__(self, union, req_id=0, trace_id=b''):
        self.union = union
        if req_id == 0:
            # If no request id is specified, generate a random id.
            req_id = mk_ctrl_req_id()
        self.req_id = req_id
        self.trace_id = trace_id

    @classmethod
    def from_raw(cls, raw):
        try:
            p = cls.P_CLS.from_bytes_packed(raw).as_builder()
        except capnp.lib.capnp.KjException as e:
            raise SCIONParseError("Unable to parse %s capnp message: %s" % (cls.NAME, e)) from None
        return cls.from_proto(p)

    @classmethod
    def _from_union(cls, p, union):  # pragma: no cover
        return cls(union, p.reqId, p.traceId)

    def proto(self):
        field = self.type()
        return self.P_CLS.new_message(**{
            field: self.union.proto(),
            "reqId": self.req_id,
            "traceId": self.trace_id,
        })

    def req_id_str(self):
        return "%016x" % self.req_id

    def __str__(self):
        return "%s(%dB): req_id=%s trace_id=%s %s" % (
            self.NAME, len(self), self.req_id_str(), self.trace_id, self.union)

    def new_signed_pld(self):
        return SignedCtrlPayload.from_values(self.proto().to_bytes_packed())

    def pack(self):  # pragma: no cover
        return self.new_signed_pld().pack()


def mk_ctrl_req_id():
    return random.randrange(1, 1 << 64)
