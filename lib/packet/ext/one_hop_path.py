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
:mod:`one_hop_path` --- one_hop_path extension header
=====================================================
"""
# Stdlib
import struct

# SCION
from lib.packet.ext_hdr import HopByHopExtension
from lib.packet.path import SCIONPath
from lib.packet.opaque_field import HopOpaqueField, InfoOpaqueField
from lib.types import ExtHopByHopType
from lib.util import Raw


class OneHopPathExt(HopByHopExtension):
    """
    0B       1        2        3        4        5        6        7
    +--------+--------+--------+--------+--------+--------+--------+--------+
    | xxxxxxxxxxxxxxxxxxxxxxxx |               IFID                |  0x00  |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                             Info Field                                |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                             Hop Field 1                               |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    |                             Hop Field 2                               |
    +--------+--------+--------+--------+--------+--------+--------+--------+
    """
    NAME = "OneHopPath"
    EXT_TYPE = ExtHopByHopType.ONE_HOP_PATH
    LEN = 5 + InfoOpaqueField.LEN + 2*HopOpaqueField.LEN

    def __init__(self, raw=None):
        self.ifid = 0
        self.info = InfoOpaqueField()
        self.info.hops = 2
        self.hf1 = HopOpaqueField()
        self.hf2 = HopOpaqueField()
        super().__init__(raw)

    def _parse(self, raw):
        super()._parse(raw)
        data = Raw(raw, self.NAME, self.LEN)
        self.ifid = struct.unpack("!I", data.pop(4))[0]

    @classmethod
    def from_values(cls, ifid, info, hf1, hf2):  # pragma: no cover
        inst = cls()
        inst.ifid = ifid
        inst.info = info
        inst.hf1 = hf1
        inst.hf2 = hf2
        return inst

    def pack(self):
        raw = struct.pack("!I", self.ifid)
        raw += b"\x00"  # Padding
        raw += self.to_path().pack()
        return raw

    def to_path(self):
        return SCIONPath.from_values(self.info, [self.hf1, self.hf2])

    def __str__(self):
        return "One-hop path: %s" % self.to_path()
