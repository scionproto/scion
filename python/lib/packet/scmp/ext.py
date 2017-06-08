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
:mod:`ext` --- SCMP hop-by-hop extension header
=========================================================
"""
# Stdlib
import struct

# SCION
from lib.packet.ext_hdr import HopByHopExtension
from lib.flagtypes import FlagBase
from lib.types import ExtHopByHopType
from lib.util import Raw


_ExtFlags = FlagBase((
    (1, "ERROR", ""),
    (2, "HOPBYHOP", "END2END"),
))


class SCMPExt(HopByHopExtension):  # pragma: no cover
    NAME = "SCMPExt"
    EXT_TYPE = ExtHopByHopType.SCMP
    LEN = 5

    def __init__(self, raw=None):
        self.error = True
        self.hopbyhop = False
        super().__init__(raw)

    def _parse(self, raw):
        super()._parse(raw)
        data = Raw(raw, self.NAME, self.LEN)
        self._parse_flags(data.pop(1))

    def _parse_flags(self, flags):
        self.error = bool(flags & _ExtFlags.ERROR)
        self.hopbyhop = bool(flags & _ExtFlags.HOPBYHOP)

    @classmethod
    def from_values(cls, error=True, hopbyhop=False):  # pragma: no cover
        inst = cls()
        inst.error = error
        inst.hopbyhop = hopbyhop
        return inst

    def pack(self):
        raw = struct.pack("!Bxxxx", self._pack_flags())
        self._check_len(raw)
        return raw

    def _pack_flags(self):
        flags = 0
        if self.error:
            flags |= _ExtFlags.ERROR
        if self.hopbyhop:
            flags |= _ExtFlags.HOPBYHOP
        return flags

    def __str__(self):
        flags = self._pack_flags()
        return "%s(%sB): flags: %s" % (
            self.NAME, len(self), _ExtFlags.to_str(flags))
