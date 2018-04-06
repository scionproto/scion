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
# External
import capnp  # noqa

# SCION
from datetime import datetime
import proto.rev_info_capnp as P
from lib.errors import SCIONBaseError
from lib.packet.packet_base import Cerealizable
from lib.packet.scion_addr import ISD_AS
from lib.util import iso_timestamp


class ProtoLinkType(object):
    CORE = "core"
    PARENT = "parent"
    CHILD = "child"
    PEER = "peer"


class RevInfoValidationError(SCIONBaseError):
    """Validation of RevInfo failed"""


class RevocationInfo(Cerealizable):
    """
    Class containing revocation information.
    """
    NAME = "RevocationInfo"
    P_CLS = P.RevInfo

    @classmethod
    def from_values(cls, isd_as, if_id, link_type, timestamp, ttl=10):
        """
        Returns a RevocationInfo object with the specified values.

        :param ISD_AS isd_as: The ISD_AS of the issuer of the revocation.
        :param int if_id: ID of the interface to be revoked
        :param str link_type: Link type of the revoked interface
        :param int timestamp: Revocation creation time
        :param int TTL: Revocation validity period in seconds
        """
        p = cls.P_CLS.new_message(isdas=int(isd_as), ifID=if_id, linkType=link_type,
                                  timestamp=timestamp, ttl=ttl)
        return cls(p)

    def isd_as(self):
        return ISD_AS(self.p.isdas)

    def validate(self):
        if self.p.timestamp > datetime.now():
            raise RevInfoValidationError("Invalid timestamp: %s" % self.p.timestamp)
        if self.p.ttl < 10:
            raise RevInfoValidationError("Invalid TTL: %s" % self.p.ttl)
        if self.p.ifID == 0:
            raise RevInfoValidationError("Invalid ifID: %d" % self.p.ifID)
        self.isd_as()

    def cmp_str(self):
        b = []
        b.append(self.p.isdas.to_bytes(8, 'big'))
        b.append(self.p.ifID.to_bytes(8, 'big'))
        b.append(self.p.epoch.to_bytes(8, 'big'))
        b.append(self.p.nonce)
        return b"".join(b)

    def __eq__(self, other):
        if other is None:
            logging.error("Other RevInfo object is None.")
            return False
        return self.cmp_str() == other.cmp_str()

    def __hash__(self):
        return hash(self.cmp_str())

    def short_desc(self):
        return "RevInfo: %s IF: %d Link type: %s Timestamp: %s TTL: %d" % (
            self.isd_as(), self.p.ifID, self.p.link_type, iso_timestamp(self.p.timestamp / 1000000), self.p.ttl)
