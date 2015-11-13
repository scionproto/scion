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
from lib.crypto.certificate import CertificateChain, TRC
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
    LEN = ISD_AD.LEN + 4

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param raw: packed packet.
        :type raw: bytes
        """
        super().__init__()
        self.isd_id = None
        self.ad_id = None
        self.version = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.isd_id, self.ad_id = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.version = struct.unpack("!I", data.pop(4))[0]

    @classmethod
    def from_values(cls, isd_id, ad_id, version):
        inst = cls()
        inst.isd_id = isd_id
        inst.ad_id = ad_id
        inst.version = version
        return inst

    def pack(self):
        packed = []
        packed.append(ISD_AD(self.isd_id, self.ad_id).pack())
        packed.append(struct.pack("!I", self.version))
        return b"".join(packed)

    def short_desc(self):  # pragma: no cover
        return "%s-%sv%s" % (self.isd_id, self.ad_id, self.version)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return (
            "[%s(%dB): Dest ISD/AD: %d-%d Version:%d]" % (
                self.NAME, len(self), self.isd_id, self.ad_id, self.version))


class CertChainReply(CertMgmtBase):
    """
    Certificate Chain Reply packet.

    :ivar cert_chain: requested certificate chain's content.
    :type cert_chain: `CertificateChain`
    """
    NAME = "CertChainReply"
    PAYLOAD_TYPE = CertMgmtType.CERT_CHAIN_REPLY

    def __init__(self, raw=None):  # pragma: no cover
        """
        Initialize an instance of the class CertChainReply.

        :param raw: packed packet.
        :type raw: bytes
        """
        super().__init__()
        self.cert_chain = CertificateChain()
        if raw:
            self._parse(raw)

    def _parse(self, raw):  # pragma: no cover
        """
        Parse a string of bytes and populate the instance variables.

        :param raw: packed packet.
        :type raw: bytes
        """
        data = Raw(raw, self.NAME)
        self.cert_chain = CertificateChain(data.pop().decode('utf-8'))

    @classmethod
    def from_values(cls, cert_chain):
        """
        Return a Certificate Chain Reply with the values specified.

        :param cert_chain: requested certificate chain.
        :type cert_chain: :class:`CertificateChain`
        :returns: the newly created CertChainReply instance.
        :rtype: :class:`CertChainReply`
        """
        inst = cls()
        inst.cert_chain = cert_chain
        return inst

    def pack(self):  # pragma: no cover
        return self.cert_chain.pack()

    def short_desc(self):  # pragma: no cover
        return "%s-%sv%s" % self.cert_chain.get_leaf_isd_ad_ver()

    def __len__(self):  # pragma: no cover
        return len(self.cert_chain.pack())

    def __str__(self):
        isd, ad, ver = self.cert_chain.get_leaf_isd_ad_ver()
        return ("[%s(%dB): Isd:%d Ad:%d Version:%d, "
                "Cert_chain len:%d]" %
                (self.NAME, len(self), isd, ad, ver,
                 len(self.cert_chain.pack())))


class TRCRequest(CertMgmtBase):
    NAME = "TRCRequest"
    PAYLOAD_TYPE = CertMgmtType.TRC_REQ
    LEN = ISD_AD.LEN + 4

    def __init__(self, raw=None):  # pragma: no cover
        """
        :param raw: packed packet.
        :type raw: bytes
        """
        super().__init__()
        self.isd_id = None
        self.ad_id = None
        self.version = None
        if raw:
            self._parse(raw)

    def _parse(self, raw):
        data = Raw(raw, self.NAME, self.LEN)
        self.isd_id, self.ad_id = ISD_AD.from_raw(data.pop(ISD_AD.LEN))
        self.version = struct.unpack("!I", data.pop(4))[0]

    @classmethod
    def from_values(cls, isd_id, ad_id, version):
        inst = cls()
        inst.isd_id = isd_id
        inst.ad_id = ad_id
        inst.version = version
        return inst

    def pack(self):
        packed = []
        packed.append(ISD_AD(self.isd_id, self.ad_id).pack())
        packed.append(struct.pack("!I", self.version))
        return b"".join(packed)

    def __len__(self):  # pragma: no cover
        return self.LEN

    def __str__(self):
        return (
            "[%s(%dB):Dest ISD: %d Version:%d]" % (self.NAME, len(self),
                                                   self.isd_id, self.version))


class TRCReply(CertMgmtBase):
    """
    TRC Reply payload.

    :ivar trc: requested TRC's content.
    :type trc: bytes
    """
    NAME = "TRCReply"
    PAYLOAD_TYPE = CertMgmtType.TRC_REPLY

    def __init__(self, raw=None):  # pragma: no cover
        """
        Initialize an instance of the class TRCReply.

        :param raw: packed packet.
        :type raw: bytes
        """
        super().__init__()
        self.trc = TRC()
        if raw is not None:
            self._parse(raw)

    def _parse(self, raw):  # pragma: no cover
        """
        Parse a string of bytes and populate the instance variables.

        :param raw: packed packet.
        :type raw: bytes
        """
        data = Raw(raw, self.NAME)
        self.trc = TRC(data.pop().decode('utf-8'))

    @classmethod
    def from_values(cls, trc):
        """
        Return a TRC Reply with the values specified.

        :param trc: requested TRC.
        :type trc: :class:`TRC`
        :returns: the newly created TRCReply instance.
        :rtype: :class:`TRCReply`
        """
        inst = cls()
        inst.trc = trc
        return inst

    def pack(self):  # pragma: no cover
        return self.trc.pack()

    def __len__(self):  # pragma: no cover
        return len(self.trc.pack())

    def __str__(self):
        isd, ver = self.trc.get_isd_ver()
        return "[%s(%dB): isd_id:%s version:%s trc:%s]" % (
            self.NAME, len(self), isd, ver,
            hexlify(self.trc.to_json()).decode())


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
