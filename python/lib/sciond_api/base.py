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
:mod:`base` --- Base class for SCIOND messages
==============================================
"""
# External
import capnp  # noqa

# SCION
import proto.sciond_capnp as P
from lib.errors import SCIONParseError
from lib.packet.packet_base import CerealBox
from lib.sciond_api.as_req import SCIONDASInfoRequest, SCIONDASInfoReply
from lib.sciond_api.if_req import SCIONDIFInfoReply, SCIONDIFInfoRequest
from lib.sciond_api.path_req import SCIONDPathRequest, SCIONDPathReply
from lib.sciond_api.revocation import SCIONDRevNotification, SCIONDRevReply
from lib.sciond_api.service_req import SCIONDServiceInfoReply, SCIONDServiceInfoRequest
from lib.types import SCIONDMsgType


class SCIONDMsg(CerealBox):  # pragma: no cover
    NAME = "SCIONDMsg"
    P_CLS = P.SCIONDMsg
    CLASS_FIELD_MAP = {
        SCIONDPathRequest: SCIONDMsgType.PATH_REQUEST,
        SCIONDPathReply: SCIONDMsgType.PATH_REPLY,
        SCIONDASInfoRequest: SCIONDMsgType.AS_REQUEST,
        SCIONDASInfoReply: SCIONDMsgType.AS_REPLY,
        SCIONDRevNotification: SCIONDMsgType.REVOCATION,
        SCIONDRevReply: SCIONDMsgType.REVOCATIONREPLY,
        SCIONDIFInfoRequest: SCIONDMsgType.IF_REQUEST,
        SCIONDIFInfoReply: SCIONDMsgType.IF_REPLY,
        SCIONDServiceInfoRequest: SCIONDMsgType.SERVICE_REQUEST,
        SCIONDServiceInfoReply: SCIONDMsgType.SERVICE_REPLY,
    }

    def __init__(self, contents, id):
        super().__init__(contents)
        self.id = id

    @classmethod
    def from_raw(cls, raw):
        try:
            p = cls.P_CLS.from_bytes_packed(raw).as_builder()
        except capnp.lib.capnp.KjException as e:
            raise SCIONParseError("Unable to parse %s capnp message: %s" % (cls.NAME, e)) from None
        return cls.from_proto(p)

    @classmethod
    def _from_contents(cls, p, contents):  # pragma: no cover
        return cls(contents, p.id)

    def proto(self):
        field = self.type()
        return self.P_CLS.new_message(**{"id": self.id, field: self.contents.proto()})

    def __str__(self):
        return "%s(%dB): id=%s %s" % (self.NAME, len(self), self.id, self.contents)
