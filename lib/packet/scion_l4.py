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
:mod:`scion_l4` --- Layer 4 handling
====================================
"""
# SCION
from lib.defines import L4_UDP, L4_PROTOS
from lib.errors import SCIONParseError
from lib.packet.packet_base import L4HeaderBase, PayloadRaw
from lib.packet.scion_udp import SCIONUDPHeader


class SCIONL4Unknown(L4HeaderBase):  # pragma: no cover
    NAME = "Unknown"

    def __init__(self, proto):
        raise NotImplementedError

    def from_values(self):
        raise NotImplementedError

    def _parse(self):
        raise NotImplementedError

    def update(self):
        raise NotImplementedError

    def __len__(self):
        return 0

    def __str__(self):
        return "[Unknown L4 protocol header]"


def parse_l4_hdr(proto, data, src=None, dst=None):
    if proto == L4_UDP:
        raw_hdr = data.pop(SCIONUDPHeader.LEN)
        payload = PayloadRaw(data.get())
        assert src
        assert dst
        return SCIONUDPHeader((src, dst, raw_hdr, payload))
    if proto in L4_PROTOS:
        return None
    raise SCIONParseError("Unsupported L4 protocol type: %s" % proto)
