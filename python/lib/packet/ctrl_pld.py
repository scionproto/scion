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
    def from_values(cls, cpld_raw, sig_type=ProtoSignType.NONE, sig_src=b""):
        s = ProtoSign.from_values(sig_type, sig_src)
        return cls(cls.P_CLS.new_message(blob=cpld_raw, sign=s.p))

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

    @classmethod
    def from_raw(cls, raw):
        try:
            p = cls.P_CLS.from_bytes_packed(raw).as_builder()
        except capnp.lib.capnp.KjException as e:
            raise SCIONParseError("Unable to parse %s capnp message: %s" % (cls.NAME, e)) from None
        return cls.from_proto(p)

    def new_signed_pld(self):
        return SignedCtrlPayload.from_values(self.proto().to_bytes_packed())

    def pack(self):  # pragma: no cover
        return self.new_signed_pld().pack()
