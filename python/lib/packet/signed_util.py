# Copyright 2018 ETH Zurich
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
:mod:`signed_util` --- Utility for signed control payloads
=========================================
"""

# Std
import re

# SCION
from lib.errors import SCIONKeyError, SCIONParseError, SCIONVerificationError
from lib.packet.cert_mgmt import CertChainReply, TRCReply
from lib.packet.ctrl_pld import CtrlPayload, SignedCtrlPayload
from lib.packet.packet_base import Serializable
from lib.packet.proto_sign import ProtoSign, ProtoSignType
from lib.packet.scion_addr import ISD_AS
from lib.trust_store import TrustStore


def create_sign(ia: ISD_AS, chain_ver: int, trc_ver: int) -> ProtoSign:
    """
    Create ProtoSign for the specified values with ed25519 as the singing algorithm.

    :param ISD_AS ia: ISD-AS of the signing AS.
    :param int chain_ver: Version of the certificate authenticating the signing key.
    :param int trc_ver: Version of the TRC authenticating the certificate chain.
    :returns: The sign object
    :rtype: ProtoSign
    """
    sign = DefaultSignSrc.from_values(ia, chain_ver, trc_ver)
    return ProtoSign.from_values(ProtoSignType.ED25519, sign.pack())


class Signer(object):
    """
    Basic signer to create signed control payloads.
    """

    def __init__(self, sign: ProtoSign, key: bytes) -> None:
        """
        :param ProtoSign sign: The ProtoSign used to sign each control payload.
        :param bytes key: The key used to sign each control payload authenticated by sign.
        """
        self._sign = sign
        self._key = key

    def sign(self, pld: CtrlPayload) -> SignedCtrlPayload:
        """
        Creates a signed version of the supplied control payload.

        :param CtrlPayload pld: The control payload to be signed
        :returns: the signed control payload
        :rtype: SignedCtrlPayload
        :raises: ProtoSignError
        """
        sig_pld = SignedCtrlPayload.from_values(
            pld.proto().to_bytes_packed(), self._sign.copy())
        sig_pld.sign(self._key)
        return sig_pld


class Verifier(object):
    """
    Basic verifier to verify signed control payloads.
    """

    def __init__(self, trust_store: TrustStore) -> None:
        """
        :param TrustStore trust_store: The trust store used to fetch the trust objects.
        """
        self._trust_store = trust_store

    def verify(self, spld: SignedCtrlPayload) -> bool:
        """
        Verify checks if the signed control payload can be verified.
        If not, an error is raised.

        :param SignedCtrlPayload spld: the signed control payload to be verified.
        :returns: whether the verification was successful.
        :rtype: bool
        :raises: SCIONVerificationError
        """
        try:
            cpld = spld.pld()
        except SCIONParseError as e:
            raise SCIONVerificationError(
                "Unable to unpack control payload. Error: %s" % e) from None
        if self.ignore_sign(cpld):
            return True
        try:
            vkey = self.get_verifying_key(spld.psign)
        except (SCIONKeyError, SCIONParseError, SCIONVerificationError) as e:
            raise SCIONVerificationError("Unable to fetch verifying key. Error: %s" % e) from None
        return spld.verify(vkey)

    def ignore_sign(self, cpld: CtrlPayload) -> bool:
        """
        Check if the signature shall be ignored for this type of control payload.
        CertChainReply and TRCReply are ignored to avoid dependency cycles.

        :param CtrlPayload cpld: The control payload.
        :returns: whether the signature shall be ignored.
        :rtype: bool
        """
        if type(cpld.union.union) in (CertChainReply, TRCReply,):
            return True
        return False

    def get_verifying_key(self, sign: ProtoSign) -> bytes:
        """
        Parses the sign src and fetches the authenticated verifying key.
        In case the certificate chain or TRC are not present, a SCIONKeyError is thrown.
        In case the the certificate chain or TRC are not valid anymore, a
        SCIONVerificationError is thrown.

        :param ProtoSign sign: The sign of the signed control payload to be verified.
        :returns: the verifying key
        :rtype: bytes
        :raises SCIONSignSrcError, SCIONKeyError, SCIONVerificationError
        """
        if sign.p.type == ProtoSignType.NONE:
            return bytes(0)
        src = DefaultSignSrc(sign.p.src)
        chain = self._trust_store.get_cert(src.ia, src.chain_ver)
        if not chain:
            raise SCIONKeyError("Chain (%sv%s) not found" % (src.ia, src.chain_ver)) from None
        trc = self._trust_store.get_trc(src.ia[0], src.trc_ver)
        if not trc:
            raise SCIONKeyError("TRC (%sv%s) not found" % (src.ia[0], src.trc_ver)) from None
        max_trc = self._trust_store.get_trc(src.ia[0])
        trc.check_active(max_trc)
        chain.verify(chain.as_cert.subject, trc)
        return chain.as_cert.subject_sig_key


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
        self.ia
        self.trc_ver
        self.chain_ver
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
        self.chain_ver = groups[0][1]
        self.trc_ver = groups[0][2]

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
