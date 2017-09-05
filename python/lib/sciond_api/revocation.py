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
:mod:`revocation` --- SCIOND revocation notification
====================================================
"""
# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.packet.path_mgmt.rev_info import RevocationInfo
from lib.sciond_api.base import SCIONDMsgBase
from lib.types import (
    SCIONDMsgType as SMT,
    TypeBase,
)


class SCIONDRevNotification(SCIONDMsgBase):
    """Revocation notification message."""
    NAME = "RevNotification"
    MSG_TYPE = SMT.REVOCATION
    P_CLS = P.RevNotification

    def __init__(self, p, id_):
        super().__init__(p, id_)
        self._rev_info = None

    @classmethod
    def from_values(cls, id_, rev_info):
        p = cls.P_CLS.new_message(revInfo=rev_info.p)
        return cls(p, id_)

    def rev_info(self):
        if not self._rev_info:
            self._rev_info = RevocationInfo(self.p.revInfo)
        return self._rev_info

    def short_desc(self):
        return self.rev_info().short_desc()


class SCIONDRevReply(SCIONDMsgBase):  # pragma: no cover
    """Revocation reply."""
    NAME = "RevReply"
    MSG_TYPE = SMT.REVOCATIONREPLY
    P_CLS = P.RevReply

    @classmethod
    def from_values(cls, id_, result):
        p = cls.P_CLS.new_message(result=result)
        return cls(p, id_)

    def short_desc(self):
        return "result=%d" % SCIONDRevReplyStatus.describe(self.result)


class SCIONDRevReplyStatus(TypeBase):  # pragma: no cover
    VALID = 0
    STALE = 1
    INVALID = 2
    UNKNOWN = 3

    @classmethod
    def describe(cls, code):
        if code == cls.VALID:
            return "Revocation is valid."
        if code == cls.STALE:
            return "Revocation is stale."
        if code == cls.INVALID:
            return "Revocation is invalid."
        if code == cls.UNKNOWN:
            return "Revocation state unknown."
        return "Unknown result code."
