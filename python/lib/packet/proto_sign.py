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
import time
import re
# External
import capnp  # noqa

# SCION
import proto.sign_capnp as P
from lib.crypto.asymcrypto import sign, verify
from lib.packet.packet_base import Cerealizable, Serializable
from lib.packet.scion_addr import ISD_AS
from lib.errors import SCIONBaseError, SCIONParseError
from lib.util import iso_timestamp


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

    def sign(self, key, msg, ts=None):
        assert isinstance(msg, bytes), type(msg)
        if len(msg) == 0:
            raise ProtoSignError("Message is empty (sign)")
        if len(self.p.signature) > 0:
            raise ProtoSignError("Signature already present")
        if ts is None:
            ts = time.time()
        self.p.timestamp = int(ts)
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
        b.append(self.p.timestamp.to_bytes(8, 'big'))
        return b"".join(b)

    def _sig_input(self, msg):
        return b"".join([msg, self.sig_pack(incl_sig=False)])

    def __str__(self):
        return "%s: type: %s src: %s ts: %s" % (self.NAME, self.p.type,
                                                self.p.src, iso_timestamp(self.p.timestamp))


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


class DefaultSignSrc(Serializable):
    """
    Default src for proto.Sign
    """

    PREFIX = "DEFAULT: "
    FMT_RE = re.compile(r"^" + PREFIX + r"IA: (\S+) CHAIN: (\d+) TRC: (\d+)$")

    def __init__(self, raw: bytes = None) -> None:
        """
        :param bytes raw: The raw src.
        :raises: SCIONParseError
        """
        self.ia = ISD_AS()
        self.trc_ver = 0
        self.chain_ver = 0
        super().__init__(raw)

    def _parse(self, raw: bytes) -> None:
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            raise SCIONParseError(e) from None
        groups = self.FMT_RE.findall(decoded)
        if not groups:
            raise SCIONParseError("Input does not match pattern. Decoded: %s" % decoded) from None
        try:
            self.ia = ISD_AS(groups[0][0])
        except SCIONParseError as e:
            raise SCIONParseError(
                "Unable to parse IA. Decoded: %s error: %s" % (decoded, e)) from None
        self.chain_ver = int(groups[0][1])
        self.trc_ver = int(groups[0][2])

    @classmethod
    def from_values(cls, ia: ISD_AS, chain_ver: int, trc_ver: int) -> 'DefaultSignSrc':
        """
        :param ISD_AS ia: ISD-AS of the signing AS.
        :param int chain_ver: Version of the certificate authenticating the signing key.
        :param int trc_ver: Version of the TRC authenticating the certificate chain.
        :returns: the sign src
        :rtype: DefaultSignSrc
        """
        inst = cls()
        inst.ia = ia
        inst.chain_ver = chain_ver
        inst.trc_ver = trc_ver
        return inst

    def pack(self) -> bytes:
        return str(self).encode("utf-8")

    def __len__(self) -> int:
        return len(self.pack())

    def __str__(self) -> str:
        return "%sIA: %s CHAIN: %s TRC: %s" % (
            DefaultSignSrc.PREFIX, self.ia, self.chain_ver, self.trc_ver)
