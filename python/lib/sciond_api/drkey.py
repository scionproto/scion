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
:mod:`drkey` --- SCIOND DRKey request
====================================================
"""
# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P

from lib.drkey.drkey_mgmt import DRKeyProtocolRequest, DRKeyProtocolReply
from lib.sciond_api.base import SCIONDMsgBase
from lib.types import SCIONDMsgType as SMT


class SCIONDDRKeyRequest(SCIONDMsgBase):
    """protocol DRKey request message."""
    NAME = "DRKeyRequest"
    MSG_TYPE = SMT.DRKEY_REQUEST
    P_CLS = P.DRKeyRequest

    def __init__(self, p, id_):
        super().__init__(p, id_)
        self._request = None

    @classmethod
    def from_values(cls, id_, params):
        request = DRKeyProtocolRequest.from_values(params)
        p = cls.P_CLS.new_message(request=request.p)
        return cls(p, id_)

    def request(self):
        if not self._request:
            self._request = DRKeyProtocolRequest(self.p.request)
        return self._request

    def short_desc(self):
        return self.request().short_desc()


class SCIONDDRKeyError:  # pragma: no cover
    OK = 0
    CS_TIMEOUT = 1
    INTERNAL = 2

    @classmethod
    def describe(cls, code):
        if code == cls.OK:
            return "OK"
        if code == cls.CS_TIMEOUT:
            return "SCIOND timed out while requesting protocol drkey."
        if code == cls.INTERNAL:
            return "SCIOND experienced an internal error."
        return "Unknown error"


class SCIONDDRKeyReply(SCIONDMsgBase):
    """protocol DRKey reply message."""
    NAME = "DRKeyReply"
    MSG_TYPE = SMT.DRKEY_REPLY
    P_CLS = P.DRKeyReply

    def __init__(self, p, id_):
        super().__init__(p, id_)
        self._reply = None

    @classmethod
    def from_values(cls, id_, drkey, exp_time, timestamp, misc, code=SCIONDDRKeyError.OK):
        reply = DRKeyProtocolReply.from_values(0, drkey, exp_time, timestamp, misc)
        p = cls.P_CLS.new_message(reply=reply.p, errorCode=code)
        return cls(p, id_)

    def reply(self):
        if not self._reply:
            self._reply = DRKeyProtocolReply(self.p.reply)
        return self._reply

    def short_desc(self):
        return self.reply().short_desc()
