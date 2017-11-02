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
:mod:`proto_sign` --- Signed Capnp protos
=========================================
"""

# External
import capnp  # noqa

# SCION
import proto.sign_capnp as P
from lib.packet.packet_base import Cerealizable
from lib.crypto.asymcrypto import sign, verify
from lib.errors import SCIONBaseError


class ProtoSignError(SCIONBaseError):
    pass


class ProtoSignType(object):
    NONE = "none"
    ED25519 = "ed25519"


class ProtoSign(Cerealizable):
    NAME = "ProtoSign"
    P_CLS = P.Sign

    @classmethod
    def from_values(cls, type_=ProtoSignType.NONE, src=b""):
        assert isinstance(src, bytes), type(src)
        return cls(cls.P_CLS.new_message(type=type_, src=src))

    def sign(self, key, msg):
        assert isinstance(msg, bytes), type(msg)
        if len(msg) == 0:
            raise ProtoSignError("Message is empty (sign)")
        if len(self.p.signature) > 0:
            raise ProtoSignError("Signature already present")
        if self.p.type == ProtoSignType.ED25519:
            self.p.signature = sign(self._sig_input(msg), key)
        else:
            raise ProtoSignError("Unsupported proto signature type (sign): %s" % self.p.type)

    def verify(self, key, msg):
        assert isinstance(msg, bytes), type(msg)
        if len(msg) == 0:
            raise ProtoSignError("Message is empty (verify)")
        if self.p.type == ProtoSignType.NONE:
            return True
        if len(self.p.signature) == 0:
            raise ProtoSignError("No signature to verify")
        elif self.p.type == ProtoSignType.ED25519:
            return verify(self._sig_input(msg), self.p.signature, key)
        else:
            raise ProtoSignError("Unsupported proto signature type (verify): %s" % self.p.type)

    def sig_pack(self, incl_sig=True):
        b = [str(self.p.type).encode("utf-8"), self.p.src]
        if incl_sig:
            b.append(self.p.signature)
        return b"".join(b)

    def _sig_input(self, msg):
        return b"".join([self.sig_pack(False), msg])


class ProtoSignedBlob(Cerealizable):
    NAME = "ProtoSignedBlob"
    P_CLS = P.SignedBlob

    def __init__(self, p):
        super().__init__(p)
        self.psign = ProtoSign(self.p.sign)

    @classmethod
    def from_values(cls, data, type_=ProtoSignType.NONE, src=b""):
        s = ProtoSign.from_values(type_, src)
        return cls(cls.P_CLS.new_message(blob=data, sign=s.p))

    def sign(self, key):
        return self.psign.sign(key, self.p.blob)

    def verify(self, key):
        return self.psign.verify(key, self.p.blob)
