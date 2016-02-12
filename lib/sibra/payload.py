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
# Stdlib

# SCION
from lib.errors import SCIONParseError
from lib.packet.packet_base import SCIONPayloadBase
from lib.types import PayloadClass, SIBRAPayloadType


class SIBRAPayload(SCIONPayloadBase):  # pragma: no cover
    """
    An empty payload to allow for packet dispatching.
    """
    NAME = "SIBRAPayload"
    PAYLOAD_CLASS = PayloadClass.SIBRA
    PAYLOAD_TYPE = SIBRAPayloadType.EMPTY

    def _parse(self, raw):
        pass

    @classmethod
    def from_values(cls):
        return cls()

    def pack(self):
        return b""

    def __len__(self):
        return 0

    def __str__(self):
        return "<Empty SIBRA payload>"


def parse_sibra_payload(type_, data):
    type_map = {
        SIBRAPayloadType.EMPTY: SIBRAPayload,
    }
    if type_ not in type_map:
        raise SCIONParseError("Unsupported sibra payload type: %s", type_)
    handler = type_map[type_]
    return handler(data.pop())
