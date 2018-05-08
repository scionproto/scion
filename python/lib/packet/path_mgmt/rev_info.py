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
:mod:`rev_info` --- Revocation info payload
============================================
"""
# Stdlib
import logging
import time
# External
import capnp  # noqa

# SCION
import proto.rev_info_capnp as P
from lib.defines import MIN_REVOCATION_TTL
from lib.errors import SCIONBaseError
from lib.packet.packet_base import Cerealizable
from lib.packet.proto_sign import DefaultSignSrc, ProtoSignedBlob
from lib.packet.scion_addr import ISD_AS
from lib.types import LinkType
from lib.util import iso_timestamp


class SignedRevInfoVerificationError(SCIONBaseError):
    """Verification of SignedRevInfo failed"""


class SignedRevInfoCertFetchError(SCIONBaseError):
    """Failed to fetch cert to verify signature"""


class RevInfoValidationError(SCIONBaseError):
    """Validation of RevInfo failed"""


class RevInfoExpiredError(SCIONBaseError):
    """Active check on RevInfo failed"""


class SignedRevInfo(ProtoSignedBlob):
    """
    Wrapper for signed revocation information.
    """
    NAME = "SignedRevInfo"

    def __init__(self, p):
        super().__init__(p)
        self._rev_info = None

    def rev_info(self):
        if not self._rev_info:
            self._rev_info = RevocationInfo.from_raw(self.p.blob)
        return self._rev_info

    def verify(self, key):
        """
        Verfiy the signature
        """
        issuer = self.rev_info().isd_as()
        signer = DefaultSignSrc(self.psign.p.src).ia
        if issuer != signer:
            raise SignedRevInfoVerificationError(
                "SignedRevInfo signer (%s) does not match revocation issuer (%s)" %
                (signer, issuer))
        if not super().verify(key):
            raise SignedRevInfoVerificationError("Failed to verify RevInfo signature!")

    def __eq__(self, other):
        return self.rev_info().cmp_str() == other.rev_info().cmp_str()

    def __hash__(self):
        return hash(self.rev_info().cmp_str())

    def short_desc(self):
        return "%s:\n%s\n%s" % (self.NAME, self.rev_info().short_desc(), self.psign)


class RevocationInfo(Cerealizable):
    """
    Class containing revocation information.
    """
    NAME = "RevocationInfo"
    P_CLS = P.RevInfo

    def __init__(self, p):
        super().__init__(p)
        self._isd_as = None

    @classmethod
    def from_values(cls, isd_as, if_id, link_type, timestamp, ttl=MIN_REVOCATION_TTL):
        """
        Returns a RevocationInfo object with the specified values.

        :param ISD_AS isd_as: The ISD_AS of the issuer of the revocation.
        :param int if_id: ID of the interface to be revoked
        :param str link_type: Link type of the revoked interface
        :param int timestamp: Revocation creation timestamp in seconds
        :param int ttl: Revocation validity period in seconds
        """
        assert ttl >= MIN_REVOCATION_TTL, ttl
        return cls(cls.P_CLS.new_message(isdas=int(isd_as), ifID=if_id, linkType=link_type,
                                         timestamp=timestamp, ttl=ttl))

    def isd_as(self):
        if not self._isd_as:
            self._isd_as = ISD_AS(self.p.isdas)
        return self._isd_as

    def validate(self):
        if self.p.timestamp > int(time.time()) + 1:
            raise RevInfoValidationError("Timestamp in the future: %s" % self.p.timestamp)
        if self.p.ttl < MIN_REVOCATION_TTL:
            raise RevInfoValidationError(
                "TTL is too small: %s MinTTL: %s" % (self.p.ttl, MIN_REVOCATION_TTL))
        if self.p.ifID == 0:
            raise RevInfoValidationError("Invalid ifID: %s" % self.p.ifID)
        self.isd_as()
        if self._isd_as[0] == 0 or self._isd_as[1] == 0:
            raise RevInfoValidationError("Invalid ISD_AS: %s" % self.isd_as())

    def active(self):
        now = int(time.time())
        # Make sure the revocation timestamp is within the validity window
        assert self.p.timestamp <= now + 1, self.p.timestamp
        return now <= (self.p.timestamp + self.p.ttl)

    def cmp_str(self):
        b = []
        b.append(self.p.isdas.to_bytes(8, 'big'))
        b.append(self.p.ifID.to_bytes(8, 'big'))
        b.append(self.p.linkType.raw.to_bytes(2, 'big'))
        b.append(self.p.timestamp.to_bytes(4, 'big'))
        b.append(self.p.ttl.to_bytes(4, 'big'))
        return b"".join(b)

    def __eq__(self, other):
        if other is None:
            logging.error("Other RevInfo object is None.")
            return False
        return self.cmp_str() == other.cmp_str()

    def __hash__(self):
        return hash(self.cmp_str())

    def short_desc(self):
        return "RevInfo: %s IF: %s Link type: %s Timestamp: %s TTL: %ss" % (
            self.isd_as(), self.p.ifID, LinkType.to_str(self.p.linkType),
            iso_timestamp(self.p.timestamp), self.p.ttl)
