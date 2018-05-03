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
from lib.packet.path_mgmt.rev_info import SignedRevInfo
from lib.packet.packet_base import Cerealizable
from lib.types import TypeBase


class SCIONDRevNotification(Cerealizable):
    """Revocation notification message."""
    NAME = "RevNotification"
    P_CLS = P.RevNotification

    def __init__(self, p):
        super().__init__(p)
        self._rev_info = None

    @classmethod
    def from_values(cls, srev_info):
        p = cls.P_CLS.new_message(sRevInfo=srev_info.p)
        return cls(p)

    def srev_info(self):
        if not self._rev_info:
            self._rev_info = SignedRevInfo(self.p.sRevInfo)
        return self._rev_info

    def short_desc(self):
        return self.srev_info().short_desc()


class SCIONDRevReply(Cerealizable):  # pragma: no cover
    """Revocation reply."""
    NAME = "RevReply"
    P_CLS = P.RevReply

    @classmethod
    def from_values(cls, result):
        p = cls.P_CLS.new_message(result=result)
        return cls(p)

    def short_desc(self):
        return "result=%d" % SCIONDRevReplyStatus.describe(self.result)


class SCIONDRevReplyStatus(TypeBase):  # pragma: no cover
    VALID = 0
    STALE = 1
    INVALID = 2
    UNKNOWN = 3
    SIGFAIL = 4

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
        if code == cls.SIGFAIL:
            return "Revocation has a bad signature."
        return "Unknown result code."
