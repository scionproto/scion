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
# Stdlib
import struct
from binascii import hexlify

# SCION
from lib.errors import SCIONParseError
from lib.packet.packet_base import SCIONPayloadBase
from lib.packet.scion_addr import ISD_AD
from lib.types import CertMgmtType, PayloadClass
from lib.util import Raw


class CertMgmtBase(SCIONPayloadBase):
    PAYLOAD_CLASS = PayloadClass.CERT
    PAYLOAD_TYPE = None


class CertChainRequest(CertMgmtBase):
    NAME = "CertChainRequest"
    PAYLOAD_TYPE = CertMgmtType.CERT_CHAIN_REQ
    LEN = 2 + ISD_AD.LEN * 2 + 4 + 1

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param raw: packed packet.
        :type raw: bytes
        """
        super().__init__()
        self.ingress_if = None
        self.src_isd = None
        self.src_ad = None
        self.isd_id = None
        self.ad_id = None
        self.version = None
        self.local = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.ingress_if = struct.unpack("!H", data.pop(2))[0]
        self.src_isd, self.src_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.isd_id, self.ad_id = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.version = struct.unpack("!I", data.pop(4))[0]
        self.local = bool(data.pop(1))

    @classmethod
    def from_values(cls, ingress_if, src_isd, src_ad, isd_id, ad_id, version,
                    local=True):
        inst = cls()
        inst.ingress_if = ingress_if
        inst.src_isd = src_isd
        inst.src_ad = src_ad
        inst.isd_id = isd_id
        inst.ad_id = ad_id
        inst.version = version
        inst.local = local
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!H", self.ingress_if))
        packed.append(ISD_AD(self.src_isd, self.src_ad).pack())
        packed.append(ISD_AD(self.isd_id, self.ad_id).pack())
        packed.append(struct.pack("!I", self.version))
        packed.append(struct.pack("!B", self.local))
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return (
            "[%s(%dB): Ingress IF:%s Src ISD/AD: %d-%d "
            "Dest ISD/AD: %d-%d Version:%d Local:%s]" % (
                self.NAME, len(self), self.ingress_if, self.src_isd,
                self.src_ad, self.isd_id, self.ad_id, self.version, self.local))


class CertChainReply(CertMgmtBase):
    """
    Certificate Chain Reply packet.

    :cvar MIN_LEN: minimum length of the packet.
    :type MIN_LEN: int
    :ivar isd_id: Target certificate chain's ISD identifier.
    :type isd_id: int
    :ivar ad_id: Target certificate chain's AD identifier.
    :type ad_id: int
    :ivar version: Target certificate chain's version.
    :type version: int
    :ivar cert_chain: requested certificate chain's content.
    :type cert_chain: bytes
    """
    NAME = "CertChainReply"
    PAYLOAD_TYPE = CertMgmtType.CERT_CHAIN_REPLY
    MIN_LEN = ISD_AD.LEN + 4

    def __init__(self, raw=None):  # pragma: no cover
        """
        Initialize an instance of the class CertChainReply.

        :param raw: packed packet.
        :type raw: bytes
        """
        super().__init__()
        self.isd_id = 0
        self.ad_id = 0
        self.version = 0
        self.cert_chain = b''
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        """
        Parse a string of bytes and populate the instance variables.

        :param raw: packed packet.
        :type raw: bytes
        """
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self.isd_id, self.ad_id = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.version = struct.unpack("!I", data.pop(4))[0]
        self.cert_chain = data.pop()

    @classmethod
    def from_values(cls, isd_id, ad_id, version, cert_chain):
        """
        Return a Certificate Chain Reply with the values specified.

        :param dst: Destination address.
        :type dst: :class:`SCIONAddr`
        :param isd_id: Target certificate chain's ISD identifier.
        :type isd_id: int
        :param ad_id, ad: Target certificate chain's AD identifier.
        :type ad_id: int
        :param version: Target certificate chain's version.
        :type version: int
        :param cert_chain: requested certificate chain's content.
        :type cert_chain: bytes
        :returns: the newly created CertChainReply instance.
        :rtype: :class:`CertChainReply`
        """
        inst = cls()
        inst.isd_id = isd_id
        inst.ad_id = ad_id
        inst.version = version
        inst.cert_chain = cert_chain
        return inst

    def pack(self):
        packed = []
        packed.append(ISD_AD(self.isd_id, self.ad_id).pack())
        packed.append(struct.pack("!I", self.version))
        packed.append(self.cert_chain)
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        return self.MIN_LEN + len(self.cert_chain)

    def __str__(self):
        return ("[%s(%dB): Isd:%d Ad:%d Version:%d, "
                "Cert_chain len:%d]" %
                (self.NAME, len(self), self.isd_id, self.ad_id, self.version,
                 len(self.cert_chain)))


class TRCRequest(CertMgmtBase):
    NAME = "TRCRequest"
    PAYLOAD_TYPE = CertMgmtType.TRC_REQ
    ISD_LEN = 2
    LEN = 2 + ISD_AD.LEN + ISD_LEN + 4 + 1

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param raw: packed packet.
        :type raw: bytes
        """
        super().__init__()
        self.ingress_if = None
        self.src_isd = None
        self.src_ad = None
        self.isd_id = None
        self.version = None
        self.local = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.ingress_if = struct.unpack("!H", data.pop(2))[0]
        self.src_isd, self.src_ad = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.isd_id = struct.unpack("!H", data.pop(self.ISD_LEN))[0]
        self.version = struct.unpack("!I", data.pop(4))[0]
        self.local = bool(data.pop(1))

    @classmethod
    def from_values(cls, ingress_if, src_isd, src_ad, isd_id, version,
                    local=True):
        inst = cls()
        inst.ingress_if = ingress_if
        inst.src_isd = src_isd
        inst.src_ad = src_ad
        inst.isd_id = isd_id
        inst.version = version
        inst.local = local
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!H", self.ingress_if))
        packed.append(ISD_AD(self.src_isd, self.src_ad).pack())
        packed.append(struct.pack("!H", self.isd_id))
        packed.append(struct.pack("!I", self.version))
        packed.append(struct.pack("!B", self.local))
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return (
            "[%s(%dB): Ingress IF:%s Src ISD/AD: %d-%d "
            "Dest ISD: %d Version:%d Local:%s]" % (
                self.NAME, len(self), self.ingress_if, self.src_isd,
                self.src_ad, self.isd_id, self.version, self.local))


class TRCReply(CertMgmtBase):
    """
    TRC Reply payload.

    :cvar MIN_LEN: minimum length of the packet.
    :type MIN_LEN: int
    :ivar isd_id: Target TRC's ISD identifier.
    :type isd_id: int
    :ivar version: Target TRC's version.
    :type version: int
    :ivar trc: requested TRC's content.
    :type trc: bytes
    """
    NAME = "TRCReply"
    PAYLOAD_TYPE = CertMgmtType.TRC_REPLY
    MIN_LEN = ISD_AD.LEN + 2

    def __init__(self, raw=None):  # pragma: no cover
        """
        Initialize an instance of the class TRCReply.

        :param raw: packed packet.
        :type raw: bytes
        """
        super().__init__()
        self.isd_id = None
        self.version = None
        self.trc = b""
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):
        """
        Parse a string of bytes and populate the instance variables.

        :param raw: packed packet.
        :type raw: bytes
        """
        data = Raw(raw, self.NAME, self.MIN_LEN, min_=True)
        self.isd_id, self.version = struct.unpack("!HI", data.pop(self.MIN_LEN))
        self.trc = data.pop()

    @classmethod
    def from_values(cls, isd_id, version, trc):
        """
        Return a TRC Reply with the values specified.

        :param dst: Destination address.
        :type dst: :class:`SCIONAddr`
        :param isd_id: Target TRC's ISD identifier.
        :type isd_id: int
        :param version: Target TRC's version.
        :type version: int
        :param trc: requested TRC's content.
        :type trc: bytes
        :returns: the newly created TRCReply instance.
        :rtype: :class:`TRCReply`
        """
        inst = cls()
        # TODO: revise TRC/Cert request/replies
        inst.isd_id = isd_id
        inst.version = version
        inst.trc = trc
        return inst

    def pack(self):
        packed = []
        packed.append(struct.pack("!HI", self.isd_id, self.version))
        packed.append(self.trc)
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        return self.MIN_LEN + len(self.trc)

    def __str__(self):
        return "[%s(%dB): isd_id:%s version:%s trc:%s]" % (
            self.NAME, len(self), self.isd_id, self.version,
            hexlify(self.trc).decode())


_TYPE_MAP = {
    CertMgmtType.CERT_CHAIN_REQ: (CertChainRequest, CertChainRequest.LEN),
    CertMgmtType.CERT_CHAIN_REPLY: (CertChainReply, None),
    CertMgmtType.TRC_REQ: (TRCRequest, TRCRequest.LEN),
    CertMgmtType.TRC_REPLY: (TRCReply, None),
}


def parse_certmgmt_payload(type_, data):
    if type_ not in _TYPE_MAP:
        raise SCIONParseError("Unsupported cert management type: %s" % type_)
    handler, len_ = _TYPE_MAP[type_]
    return handler(data.pop(len_))
