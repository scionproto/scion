# Copyright 2016 ETH Zurich
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
:mod:`payload` --- SIBRA payload
================================
"""
# External
import capnp  # noqa

# SCION
import proto.sibra_capnp as P
from lib.errors import SCIONParseError
from lib.packet.packet_base import SCIONPayloadBaseProto
from lib.types import PayloadClass, SIBRAPayloadType


class SIBRAPayload(SCIONPayloadBaseProto):  # pragma: no cover
    """
    An empty payload to allow for packet dispatching.
    """
    NAME = "SIBRAPayload"
    P_CLS = P.SibraPayload
    PAYLOAD_CLASS = PayloadClass.SIBRA
    PAYLOAD_TYPE = SIBRAPayloadType.EMPTY

    @classmethod
    def from_values(cls):
        return cls(cls.P_CLS.new_message())


def parse_sibra_payload(type_, data):  # pragma: no cover
    type_map = {
        SIBRAPayloadType.EMPTY: SIBRAPayload,
    }
    if type_ not in type_map:
        raise SCIONParseError("Unsupported sibra payload type: %s", type_)
    handler = type_map[type_]
    return handler.from_raw(data.pop())
